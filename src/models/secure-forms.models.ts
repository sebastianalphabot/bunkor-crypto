import { PublicBranding } from './vault.models';

export type SecureFormFieldType =
  | 'text'
  | 'email'
  | 'phone'
  | 'date'
  | 'number'
  | 'textarea'
  | 'checkbox'
  | 'radio'
  | 'select'
  | 'file_upload'
  | 'description'
  | 'url';

export type SecureFormSubmissionStatus = 'new' | 'reviewed' | 'archived';

export interface SecureFormFieldConfig {
  max_length?: number;
  options?: string[];
  multiple_selection?: boolean;
  allowed_mime_types?: string[];
  max_file_size_bytes?: number;
  max_files?: number;
  show_label?: boolean;
  hide_background?: boolean;
}

export interface SecureFormField {
  id?: string;
  field_type: SecureFormFieldType;
  label: string;
  placeholder?: string;
  is_required: boolean;
  order: number;
  config?: SecureFormFieldConfig;
}

export interface SecureFormSection {
  id?: string;
  title: string;
  show_title?: boolean;
  order: number;
  fields: SecureFormField[];
}

export interface CreateSecureFormRequest {
  vault_id: string;
  title: string;
  description?: string;
  expires_at?: string | null;
  max_submissions?: number | null;
  notification_emails?: string[];
  send_submitter_confirmation?: boolean;
  otp_required?: boolean;
  allowed_ips?: string[] | null;
  embed_enabled?: boolean;
  allowed_embed_domains?: string[];
  encryption_mode?: SecureFormEncryptionMode;
  encryption_password?: string;
  public_key_pem?: string;
  encrypted_private_key_blob?: string;
  kdf_params?: KdfParams;
  sections: SecureFormSection[];
}

export interface UpdateSecureFormRequest {
  title?: string;
  description?: string;
  is_active?: boolean;
  notification_emails?: string[];
  send_submitter_confirmation?: boolean;
  otp_required?: boolean;
  embed_enabled?: boolean;
  allowed_embed_domains?: string[];
  encryption_password?: string;
  sections?: SecureFormSection[];
}

export interface SecureFormFeatureLimits {
  max_sections?: number;
  max_fields_per_section?: number;
  [key: string]: number | string | boolean | undefined;
}

export interface SecureFormSubmissionStatusCounts {
  new: number;
  reviewed: number;
  archived: number;
}

export interface SecureFormSummary {
  id: string;
  title: string;
  token: string;
  vault_id: string;
  vault_name: string;
  public_url: string;
  is_active: boolean;
  submission_count: number;
  expires_at: string | null;
  created_at?: string;
}

export interface SecureFormDetail extends SecureFormSummary {
  description?: string;
  max_submissions?: number | null;
  notification_emails?: string[];
  send_submitter_confirmation?: boolean;
  otp_required?: boolean;
  embed_enabled?: boolean;
  allowed_embed_domains?: string[];
  encryption_mode?: SecureFormEncryptionMode;
  encrypted_private_key_blob?: string | null;
  kdf_params?: KdfParams | null;
  sections: SecureFormSection[];
  feature_limits?: SecureFormFeatureLimits;
  submission_status_counts?: SecureFormSubmissionStatusCounts;
}

export interface SecureFormCreateResponse {
  id: string;
  token: string;
  public_url: string;
  vault_id: string;
  vault_name: string;
  title: string;
  is_active: boolean;
  submission_count: number;
  submission_status_counts: SecureFormSubmissionStatusCounts;
  sections: SecureFormSection[];
  feature_limits?: SecureFormFeatureLimits;
  created_at: string;
}

export interface SecureFormEmbedSnippet {
  embed_url: string;
  iframe_snippet: string;
}

export interface SecureFormLogoResponse {
  logo_url: string;
}

export interface SecureFormSubmissionSummary {
  id: string;
  folder_name: string;
  vault_folder_id: string;
  submitter_email: string;
  uploader_name: string;
  submitted_at: string;
  status: SecureFormSubmissionStatus;
}

// Encrypted key data as returned by the server on submission detail
export interface EncryptedKeyDataResponse {
  algorithm: 'RSA-OAEP';
  /** AES-GCM-encrypted CEK, RSA-OAEP-wrapped. Field name varies by backend version. */
  encrypted_cek?: string;
  wrapped_key?: string;   // alias used in newer API responses
  iv: string;
}

export interface SecureFormSubmissionDetail {
  id: string;
  vault_id: string;
  vault_folder_id: string;
  folder_name: string;
  submitter_email: string;
  uploader_name: string;
  submitted_at: string;
  status: SecureFormSubmissionStatus;
  encrypted_key_data: EncryptedKeyDataResponse;
  /** Never null for submissions created after the API update. */
  metadata_file_id: string | null;
  file_count: number;
  /** Attached user files — is_confirmed:false means upload never completed. */
  files: SubmissionFileEntry[];
}

export interface SecureFormSubmissionsResponse {
  count: number;
  results: SecureFormSubmissionSummary[];
}

export interface UpdateSubmissionStatusRequest {
  status: SecureFormSubmissionStatus;
}

export interface BulkUpdateStatusRequest {
  submission_ids: string[];
  status: SecureFormSubmissionStatus;
}

export interface BulkUpdateStatusResponse {
  updated: number;
  status: SecureFormSubmissionStatus;
}

// ─── Encryption / Decryption ───────────────────────────────────────────────

export type SecureFormEncryptionMode = 'server_managed' | 'zero_knowledge';

export interface KdfParams {
  algorithm?: 'PBKDF2';
  iterations: number;
  hash: string;
  salt_b64: string;
}

export interface EncryptionConfig {
  organization_id: string;
  mode: SecureFormEncryptionMode;
  public_key_pem: string;
  has_keypair: boolean;
  encrypted_private_key_blob: string | null;
  kdf_params: KdfParams | null;
  // Recovery options (added for ZK recovery feature)
  recovery_key_blob?: string | null;
  recovery_key_kdf_params?: KdfParams | null;
  totp_recovery_blob?: string | null;
  totp_recovery_kdf_params?: KdfParams | null;
  recovery_code_entries?: Array<{
    hash: string;
    blob: string;
    kdf_params: KdfParams;
    used: boolean;
  }> | null;
}

export interface ZKSetupPayload {
  mode: 'zero_knowledge';
  public_key_pem: string;
  encrypted_private_key_blob: string;
  kdf_params: KdfParams;
}

export interface SMSetupPayload {
  mode: 'server_managed';
}

export type EncryptionConfigSetupPayload = ZKSetupPayload | SMSetupPayload;

export interface ReencryptPayload {
  new_blob: string;
  new_kdf_params: KdfParams;
}

export interface DecryptionKeyResponse {
  private_key_pem: string;
}

// ─── Public Form Schema (used by submit page) ─────────────────────────────

export interface PublicFormSchema {
  page_id: string;
  title: string;
  description?: string;
  custom_logo_url: string | null;
  requires_otp: boolean;
  send_submitter_confirmation: boolean;
  max_submissions_reached: boolean;
  is_expired: boolean;
  /** Top-level key (legacy / ZK forms that embed their own key). */
  public_key_pem?: string;
  /** Org-level key alias (some backend versions use this name). */
  org_public_key_pem?: string;
  /** Nested encryption object — backend returns public key here for server-managed forms. */
  encryption?: { public_key_pem?: string };
  embed_enabled?: boolean;
  allowed_embed_domains?: string[];
  upload_link_id?: string;  // Upload link ID for initiating signed uploads
  sections: SecureFormSection[];
  // Branding (added 2026-04-11 — matches backend PublicFormSchema serialiser)
  branding?: PublicBranding;
  // Sender info (added 2026-04-11 — resolved from created_by_user_id)
  sender_name?: string | null;
  sender_email?: string | null;
  sender_organization?: string | null;
}

// OTP responses
export interface OtpSendResponse {
  message: string;
}

export interface OtpVerifyResponse {
  otp_session_token: string;
  expires_in: number;
}

// ─── Encrypted Submission ─────────────────────────────────────────────────

// Key data sent with the submission (matches API expected format)
export interface EncryptedKeyData {
  algorithm: 'RSA-OAEP';
  encrypted_cek: string;
  iv: string;
}

export interface EncryptedFilePayload {
  fieldId: string;
  filename: string;
  contentType: string;
  encryptedContent: Blob;
}

export interface EncryptedFileReferencePayload {
  fieldId: string;
  fileId: string;   // confirmed file_id from confirm-signed-upload
}

export interface EncryptedSubmission {
  encryptedMetadata: string;
  encryptedKeyData: EncryptedKeyData;
  files: EncryptedFilePayload[];
  submitterEmail?: string;
  uploaderName?: string;
  otpSessionToken?: string;
}

export interface EncryptedSubmissionSigned {
  encryptedMetadata: string;
  encryptedKeyData: EncryptedKeyData;
  files: EncryptedFileReferencePayload[];
  /** vault_folder_id returned by initiateSignedUpload — required when uploaded_files is non-empty. */
  vaultFolderId?: string;
  /**
   * Desired vault folder name hint (UTC-based, constructed client-side).
   * Used when there are no files (folder_name_hint not yet sent via initiateSignedUpload).
   * Format: {form_name}_{YYYYMMDD}_{HHmmss}_{8hex}
   */
  folderNameHint?: string;
  submitterEmail?: string;
  uploaderName?: string;
  otpSessionToken?: string;
}

// Path A — Signed URL upload (one file at a time)
export interface InitiateSignedUploadRequest {
  upload_token: string;   // = schema.upload_link_id
  field_id: string;
  filename: string;
  content_type: string;
  size: number;
  /**
   * Desired vault folder name hint (UTC-based, constructed client-side).
   * Format: {form_name}_{YYYYMMDD}_{HHmmss}_{8hex}
   * Backend uses this only on the FIRST file upload (when the folder is created).
   * Ignored if a vault_folder_id already exists for this upload session.
   */
  folder_name_hint?: string;
}

export interface InitiateSignedUploadResponse {
  file_id: string;
  upload_url: string;
  vault_folder_id: string;
}

export interface ConfirmSignedUploadRequest {
  upload_token: string;
  field_id: string;
  file_id: string;
  filename: string;
  content_type: string;
  size: number;
  encryption_algorithm: 'aes-256-gcm';
  encryption_iv: string;   // base64-encoded 12-byte IV used for AES-GCM encryption
}

export interface ConfirmSignedUploadResponse {
  file_id: string;
  is_encrypted: boolean;
}

/** File entry as returned by GET submission detail. */
export interface SubmissionFileEntry {
  file_id: string;
  name: string;
  is_confirmed: boolean;
}

export interface SubmitResponse {
  submission_id: string;
  message: string;
  confirmation_email_sent: boolean;
}

// ─── .enc file format (produced by backend FormEncryptionService) ─────────────
export interface EncFileJson {
  version: number;
  encrypted: boolean;
  cek_encrypted_b64: string;  // RSA-OAEP-encrypted AES-256 CEK
  iv_b64: string;             // 12-byte AES-GCM IV
  ciphertext_b64: string;     // encrypted payload (without GCM tag)
  tag_b64: string;            // 16-byte GCM authentication tag
}
