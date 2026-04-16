/**
 * @bunkor/crypto — SecureEmailClient
 *
 * Repository-pattern client for the full Bunkor Secure Email API lifecycle:
 * drafts, send, inbox, sent, trash, actions, attachments, vault-attach.
 *
 * Design patterns:
 *   - Repository: clean domain interface over the Bunkor Secure Email API
 *   - Template Method: auth + transport from BaseClient
 *
 * Usage:
 * ```ts
 * const mail  = new SecureEmailClient({ apiUrl: 'https://lockbox-app-…', apiToken: 'sk_…' });
 * const draft = await mail.createDraft({ subject: 'Hello', recipients: ['alice@example.com'] });
 * await mail.sendDraft(draft.email_id);
 * ```
 *
 * Licensed under the Apache License, Version 2.0
 */

import { BunkorConfig } from '../config';
import { BaseClient } from './base.client';
import {
  CreateDraftRequest, CreateDraftResponse,
  UpdateDraftRequest, UpdateDraftResponse, SendDraftResponse,
  CreateSecureEmailRequest, CreateSecureEmailResponse,
  AccessSecureEmailResponse,
  DraftsEmailsResponse, SentEmailsResponse, InboxEmailsResponse, TrashEmailsResponse,
  EmailDetailResponse, EmailActionResponse, MarkReadResponse, UnreadCountResponse,
  AddAttachmentRequest, AddAttachmentResponse,
  InitiateAttachmentUploadRequest, InitiateAttachmentUploadResponse,
  ConfirmAttachmentUploadRequest, ConfirmAttachmentUploadResponse,
  AttachVaultFileRequest, AttachVaultFileResponse,
  EmailPaginationParams,
} from '../models/email.models';

export class SecureEmailClient extends BaseClient {
  private readonly base = '/api/v1/secure-emails';

  constructor(config: BunkorConfig) {
    super(config);
  }

  // ─── Draft Lifecycle ──────────────────────────────────────────────────────

  /**
   * Create a new email draft.
   * All fields are optional — drafts can be saved incrementally.
   */
  createDraft(request: CreateDraftRequest = {}): Promise<CreateDraftResponse> {
    return this.post<CreateDraftResponse>(`${this.base}/drafts/`, request);
  }

  /** Update an existing draft (DRAFT status only). */
  updateDraft(emailId: string, request: UpdateDraftRequest): Promise<UpdateDraftResponse> {
    return this.put<UpdateDraftResponse>(`${this.base}/${emailId}/`, request);
  }

  /** Send a draft — transitions it from DRAFT → SENT and notifies recipients. */
  sendDraft(emailId: string): Promise<SendDraftResponse> {
    return this.post<SendDraftResponse>(`${this.base}/${emailId}/send/`);
  }

  // ─── Legacy Create & Send ─────────────────────────────────────────────────

  /**
   * Create and immediately send a secure email (legacy single-step flow).
   * New code should prefer `createDraft` → `sendDraft` for attachment support.
   */
  createAndSend(request: CreateSecureEmailRequest): Promise<CreateSecureEmailResponse> {
    return this.post<CreateSecureEmailResponse>(`${this.base}/`, request);
  }

  // ─── Listings ─────────────────────────────────────────────────────────────

  /** List draft emails with pagination. */
  listDrafts(params?: { page?: number; page_size?: number }): Promise<DraftsEmailsResponse> {
    return this.get<DraftsEmailsResponse>(`${this.base}/drafts/`, this.paginationParams(params));
  }

  /** List sent emails with pagination. */
  listSent(params?: { page?: number; page_size?: number; filter_expired?: boolean }): Promise<SentEmailsResponse> {
    return this.get<SentEmailsResponse>(`${this.base}/sent/`, this.paginationParams(params));
  }

  /** List received (inbox) emails with pagination. */
  listInbox(params?: { page?: number; page_size?: number; filter_expired?: boolean }): Promise<InboxEmailsResponse> {
    return this.get<InboxEmailsResponse>(`${this.base}/inbox/`, this.paginationParams(params));
  }

  /** List trashed emails with pagination. */
  listTrash(params?: { page?: number; page_size?: number }): Promise<TrashEmailsResponse> {
    return this.get<TrashEmailsResponse>(`${this.base}/trash/`, this.paginationParams(params));
  }

  // ─── Email Detail ─────────────────────────────────────────────────────────

  /** Get full email detail including encrypted content and attachments. */
  getEmail(emailId: string): Promise<EmailDetailResponse> {
    return this.get<EmailDetailResponse>(`${this.base}/${emailId}/`);
  }

  // ─── Public Access (unauthenticated) ─────────────────────────────────────

  /**
   * Access a secure email via its access token (public, no Bunkor auth).
   * Returns the encrypted content — caller decrypts with the shared password.
   */
  accessEmail(emailId: string, accessToken: string): Promise<AccessSecureEmailResponse> {
    return this.get<AccessSecureEmailResponse>(
      `${this.base}/${emailId}/access/`,
      { access_token: accessToken },
    );
  }

  // ─── Email Actions ────────────────────────────────────────────────────────

  /** Move an email to the trash. */
  trashEmail(emailId: string): Promise<EmailActionResponse> {
    return this.post<EmailActionResponse>(`${this.base}/${emailId}/trash/`);
  }

  /** Restore an email from the trash. */
  restoreEmail(emailId: string): Promise<EmailActionResponse> {
    return this.post<EmailActionResponse>(`${this.base}/${emailId}/restore/`);
  }

  /** Permanently delete an email (must be in TRASH status). */
  deleteEmail(emailId: string): Promise<void> {
    return this.delete<void>(`${this.base}/${emailId}/`);
  }

  /** Mark an email as read. */
  markAsRead(emailId: string): Promise<MarkReadResponse> {
    return this.post<MarkReadResponse>(`${this.base}/${emailId}/mark-read/`);
  }

  /** Mark an email as unread. */
  markAsUnread(emailId: string): Promise<MarkReadResponse> {
    return this.post<MarkReadResponse>(`${this.base}/${emailId}/mark-unread/`);
  }

  // ─── Utilities ────────────────────────────────────────────────────────────

  /** Get the count of unread inbox emails. */
  getUnreadCount(): Promise<UnreadCountResponse> {
    return this.get<UnreadCountResponse>(`${this.base}/unread-count/`);
  }

  // ─── Attachments — Resumable Upload ───────────────────────────────────────

  /**
   * Initiate a resumable upload for an email attachment.
   * Returns a session URL for direct provider upload (GCS / S3).
   */
  initiateAttachmentUpload(
    emailId: string,
    request: InitiateAttachmentUploadRequest,
  ): Promise<InitiateAttachmentUploadResponse> {
    return this.post<InitiateAttachmentUploadResponse>(
      `${this.base}/${emailId}/attachments/initiate-upload/`,
      request,
    );
  }

  /** Confirm a completed resumable attachment upload and register it on the email. */
  confirmAttachmentUpload(
    emailId: string,
    request: ConfirmAttachmentUploadRequest,
  ): Promise<ConfirmAttachmentUploadResponse> {
    return this.post<ConfirmAttachmentUploadResponse>(
      `${this.base}/${emailId}/attachments/confirm-upload/`,
      request,
    );
  }

  /**
   * Attach an existing vault file without re-uploading it.
   * The caller must re-wrap the file's encryption key for the email password.
   */
  attachVaultFile(
    emailId: string,
    request: AttachVaultFileRequest,
  ): Promise<AttachVaultFileResponse> {
    return this.post<AttachVaultFileResponse>(
      `${this.base}/${emailId}/attachments/attach-vault-file/`,
      request,
    );
  }

  /**
   * Add an already-uploaded attachment record to an email (legacy direct upload).
   * Prefer the resumable upload flow for large files.
   */
  addAttachment(emailId: string, request: AddAttachmentRequest): Promise<AddAttachmentResponse> {
    return this.post<AddAttachmentResponse>(`${this.base}/${emailId}/attachments/`, request);
  }

  /** Delete an attachment from an email. */
  deleteAttachment(emailId: string, attachmentId: string): Promise<void> {
    return this.delete<void>(`${this.base}/${emailId}/attachments/${attachmentId}/`);
  }

  /** Download an attachment (returns a signed URL or blob). */
  downloadAttachment(emailId: string, attachmentId: string, accessToken?: string): Promise<{ download_url: string }> {
    const params = accessToken ? { access_token: accessToken } : undefined;
    return this.get<{ download_url: string }>(
      `${this.base}/${emailId}/attachments/${attachmentId}/download/`,
      params,
    );
  }

  // ─── Helpers ──────────────────────────────────────────────────────────────

  private paginationParams(
    params?: { page?: number; page_size?: number; filter_expired?: boolean },
  ): Record<string, string | number | boolean> | undefined {
    if (!params) return undefined;
    const out: Record<string, string | number | boolean> = {};
    if (params.page           !== undefined) out['page']           = params.page;
    if (params.page_size      !== undefined) out['page_size']      = params.page_size;
    if (params.filter_expired !== undefined) out['filter_expired'] = params.filter_expired;
    return Object.keys(out).length ? out : undefined;
  }
}
