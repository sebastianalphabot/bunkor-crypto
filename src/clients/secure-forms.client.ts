/**
 * @bunkor/crypto — SecureFormsClient
 *
 * Repository-pattern client for all Secure Form CRUD, submission management,
 * encryption-config, and public form submission operations.
 *
 * Design patterns:
 *   - Repository: clean domain interface over the Bunkor Secure Forms API
 *   - Template Method: auth + transport from BaseClient
 *
 * Usage:
 * ```ts
 * const forms = new SecureFormsClient({ apiUrl: 'https://lockbox-app-…', apiToken: 'sk_…' });
 * const list  = await forms.listForms();
 * ```
 *
 * Licensed under the Apache License, Version 2.0
 */

import { BunkorConfig } from '../config';
import { BaseClient } from './base.client';
import {
  CreateSecureFormRequest, SecureFormCreateResponse,
  SecureFormDetail, SecureFormSummary,
  UpdateSecureFormRequest, SecureFormLogoResponse, SecureFormEmbedSnippet,
  SecureFormSubmissionsResponse, SecureFormSubmissionDetail,
  UpdateSubmissionStatusRequest, BulkUpdateStatusRequest, BulkUpdateStatusResponse,
  EncryptionConfig, ZKSetupPayload, ReencryptPayload,
  DecryptionKeyResponse, KdfParams,
  PublicFormSchema, OtpSendResponse, OtpVerifyResponse,
  EncryptedSubmission, EncryptedSubmissionSigned, SubmitResponse,
  InitiateSignedUploadRequest, InitiateSignedUploadResponse,
  ConfirmSignedUploadRequest, ConfirmSignedUploadResponse,
} from '../models/secure-forms.models';
import type { StrictKdfParams } from '../models/secure-package.models';

export class SecureFormsClient extends BaseClient {
  private readonly base = '/api/v1/secure-forms';

  constructor(config: BunkorConfig) {
    super(config);
  }

  // ─── Form Lifecycle ───────────────────────────────────────────────────────

  /** List all secure forms. Pass `includeInactive = true` to include deactivated forms. */
  listForms(includeInactive = false): Promise<SecureFormSummary[]> {
    return this.get<SecureFormSummary[]>(`${this.base}/`, { include_inactive: includeInactive });
  }

  /** Create a new secure form. */
  createForm(request: CreateSecureFormRequest): Promise<SecureFormCreateResponse> {
    return this.post<SecureFormCreateResponse>(`${this.base}/`, request);
  }

  /** Get full details (including sections) for a form. */
  getForm(formId: string): Promise<SecureFormDetail> {
    return this.get<SecureFormDetail>(`${this.base}/${formId}/`);
  }

  /** Update a form's title, sections, or notification settings. */
  updateForm(formId: string, request: UpdateSecureFormRequest): Promise<SecureFormDetail> {
    return this.patch<SecureFormDetail>(`${this.base}/${formId}/`, request);
  }

  /** Deactivate (soft-delete) a form. */
  deactivateForm(formId: string): Promise<void> {
    return this.delete<void>(`${this.base}/${formId}/`);
  }

  /** Upload or replace the custom logo for a form. */
  uploadLogo(formId: string, logo: Blob, filename = 'logo.png'): Promise<SecureFormLogoResponse> {
    const form = new FormData();
    form.append('logo', logo, filename);
    return this.postForm<SecureFormLogoResponse>(`${this.base}/${formId}/logo/`, form);
  }

  /** Get the HTML/iframe embed snippet for a form. */
  getEmbedSnippet(formId: string): Promise<SecureFormEmbedSnippet> {
    return this.get<SecureFormEmbedSnippet>(`${this.base}/${formId}/embed/`);
  }

  // ─── Submissions ──────────────────────────────────────────────────────────

  /** List submissions for a form with optional status filter and pagination. */
  listSubmissions(
    formId: string,
    options?: { status?: 'new' | 'reviewed' | 'archived'; page?: number; pageSize?: number },
  ): Promise<SecureFormSubmissionsResponse> {
    const params: Record<string, string | number> = {
      page:      options?.page     ?? 1,
      page_size: options?.pageSize ?? 25,
    };
    if (options?.status) params['status'] = options.status;
    return this.get<SecureFormSubmissionsResponse>(`${this.base}/${formId}/submissions/`, params);
  }

  /** Get the full decryptable detail of a single submission. */
  getSubmission(formId: string, submissionId: string): Promise<SecureFormSubmissionDetail> {
    return this.get<SecureFormSubmissionDetail>(
      `${this.base}/${formId}/submissions/${submissionId}/`,
    );
  }

  /** Update the review status of a single submission. */
  updateSubmissionStatus(
    formId: string,
    submissionId: string,
    request: UpdateSubmissionStatusRequest,
  ): Promise<SecureFormSubmissionDetail> {
    return this.patch<SecureFormSubmissionDetail>(
      `${this.base}/${formId}/submissions/${submissionId}/`,
      request,
    );
  }

  /** Bulk-update the review status of multiple submissions. */
  bulkUpdateSubmissionStatus(
    formId: string,
    request: BulkUpdateStatusRequest,
  ): Promise<BulkUpdateStatusResponse> {
    return this.patch<BulkUpdateStatusResponse>(
      `${this.base}/${formId}/submissions/bulk-status/`,
      request,
    );
  }

  /** Permanently delete a submission. */
  deleteSubmission(formId: string, submissionId: string): Promise<void> {
    return this.delete<void>(`${this.base}/${formId}/submissions/${submissionId}/`);
  }

  // ─── Encryption Config ────────────────────────────────────────────────────

  /** Get the organisation's current encryption mode and public key. */
  getEncryptionConfig(): Promise<EncryptionConfig> {
    return this.get<EncryptionConfig>(`${this.base}/encryption-config/`);
  }

  /** Switch to server-managed encryption mode. */
  setupServerManaged(): Promise<EncryptionConfig> {
    return this.post<EncryptionConfig>(`${this.base}/encryption-config/`, { mode: 'server_managed' });
  }

  /** Switch to zero-knowledge mode (caller must supply keypair). */
  setupZeroKnowledge(payload: ZKSetupPayload): Promise<EncryptionConfig> {
    return this.post<EncryptionConfig>(`${this.base}/encryption/setup/`, payload);
  }

  /** Re-encrypt the private key blob after a password change. */
  reencryptPrivateKey(payload: ReencryptPayload): Promise<EncryptionConfig> {
    return this.post<EncryptionConfig>(`${this.base}/encryption-config/reencrypt/`, payload);
  }

  /** Fetch the server-managed private key PEM (server-managed mode only). */
  getPrivateKeyPem(): Promise<DecryptionKeyResponse> {
    return this.get<DecryptionKeyResponse>(`${this.base}/decryption-key/`);
  }

  /** Fetch the SM private key PEM for recovery export (org owner only). */
  getSmRecoveryKeyPem(): Promise<{ private_key_pem: string }> {
    return this.get<{ private_key_pem: string }>(`${this.base}/decryption-key/sm-recovery/`);
  }

  // ─── Recovery ─────────────────────────────────────────────────────────────

  /** Persist all ZK recovery blobs in one call after initial setup. */
  saveRecoveryBlobs(payload: {
    recovery_key_blob?: string;
    recovery_key_kdf_params?: StrictKdfParams;
    totp_recovery_blob?: string;
    totp_recovery_kdf_params?: StrictKdfParams;
    recovery_code_entries?: Array<{ hash: string; blob: string; kdf_params: StrictKdfParams; used: boolean }>;
  }): Promise<EncryptionConfig> {
    return this.post<EncryptionConfig>(`${this.base}/encryption-config/recovery/`, payload);
  }

  /** Clear all recovery blobs (e.g. before regenerating them). */
  clearRecoveryBlobs(): Promise<void> {
    return this.delete<void>(`${this.base}/encryption-config/recovery/`);
  }

  /** Fetch a recovery code blob by its SHA-256 hash. */
  getRecoveryCodeBlob(hash: string): Promise<{ blob: string; kdf_params: KdfParams }> {
    return this.get<{ blob: string; kdf_params: KdfParams }>(
      `${this.base}/encryption-config/recovery/code/`,
      { hash },
    );
  }

  // ─── Public Form — unauthenticated submission flow ────────────────────────

  /** Get the public form schema (shown to submitters, no auth required). */
  getPublicForm(pageId: string): Promise<PublicFormSchema> {
    return this.get<PublicFormSchema>(`/api/v1/public-forms/${pageId}/`);
  }

  /** Send OTP to the submitter's email for identity verification. */
  sendOtp(pageId: string, email: string): Promise<OtpSendResponse> {
    return this.post<OtpSendResponse>(`/api/v1/public-forms/${pageId}/send-otp/`, { email });
  }

  /** Verify OTP and receive a session token for the submission. */
  verifyOtp(pageId: string, email: string, otp: string): Promise<OtpVerifyResponse> {
    return this.post<OtpVerifyResponse>(`/api/v1/public-forms/${pageId}/verify-otp/`, {
      email,
      otp_code: otp,
    });
  }

  /**
   * Submit a form with inline encrypted files (legacy path A — small files).
   * The `files` field carries base64 encrypted blobs directly.
   */
  submitForm(
    pageId: string,
    submission: EncryptedSubmission,
  ): Promise<SubmitResponse> {
    return this.post<SubmitResponse>(`/api/v1/public-forms/${pageId}/submit/`, submission);
  }

  /**
   * Submit a form with signed-URL uploaded files (path B — large files).
   * Files must already be uploaded via `initiateSignedUpload` + GCS/S3 PUT + `confirmSignedUpload`.
   */
  submitFormSigned(
    pageId: string,
    submission: EncryptedSubmissionSigned,
  ): Promise<SubmitResponse> {
    return this.post<SubmitResponse>(`/api/v1/public-forms/${pageId}/submit/`, submission);
  }

  // ─── Signed Upload Flow ───────────────────────────────────────────────────

  /** Initiate a signed URL upload for a form file attachment. */
  initiateSignedUpload(
    pageId: string,
    request: InitiateSignedUploadRequest,
  ): Promise<InitiateSignedUploadResponse> {
    return this.post<InitiateSignedUploadResponse>(
      `/api/v1/public-forms/${pageId}/initiate-signed-upload/`,
      request,
    );
  }

  /** Confirm a successful signed-URL upload and register the file. */
  confirmSignedUpload(
    pageId: string,
    request: ConfirmSignedUploadRequest,
  ): Promise<ConfirmSignedUploadResponse> {
    return this.post<ConfirmSignedUploadResponse>(
      `/api/v1/public-forms/${pageId}/confirm-signed-upload/`,
      request,
    );
  }
}
