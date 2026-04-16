/**
 * @bunkor/crypto — Vault Domain Models
 *
 * Pure TypeScript models for all vault, file, folder, sharing, and audit
 * operations against the Bunkor API. No Angular or framework dependencies.
 *
 * Licensed under the Apache License, Version 2.0
 */

// ============================================================================
// Storage / Provider
// ============================================================================

export type StorageProvider = 'gcs' | 's3' | 'azure' | 'local' | 'bunkor';
export type DownloadMethod  = 'provider' | 'bunkor';

/** Files >= this size MUST use provider-managed download (never Bunkor proxy). */
export const PROVIDER_DOWNLOAD_THRESHOLD_BYTES = 20 * 1024 * 1024; // 20 MB

// ============================================================================
// Vault
// ============================================================================

export interface Vault {
  id: string;
  name: string;
  organization_id: string;
  storage_provider: StorageProvider;
  storage_bucket?: string;
  storage_region?: string;
  storage_path_prefix?: string;
  is_encrypted: boolean;
  is_locked: boolean;
  total_storage_bytes: number;
  file_count: number;
  created_at: string;
  created_by_user_id?: string;
}

export interface CreateVaultRequest {
  name: string;
  storage_provider?: StorageProvider;
  storage_bucket?: string;
  storage_region?: string;
  storage_path_prefix?: string;
}

export interface CreateVaultResponse {
  vault_id: string;
  name: string;
  organization_id: string;
  storage_provider: StorageProvider;
  created_at: string;
  message: string;
}

export interface ListVaultsResponse {
  vaults: Vault[];
  total_count: number;
}

export interface RenameVaultRequest {
  name: string;
}

export interface RenameVaultResponse {
  id: string;
  name: string;
  organization_id: string;
  storage_provider: string;
  is_encrypted: boolean;
  is_locked: boolean;
  created_at: string;
  message: string;
}

// ============================================================================
// Files
// ============================================================================

export interface VaultFile {
  id: string;
  name: string;
  size: number;
  content_type: string;
  created_at: string;
  storage_url: string;
  is_cloud_stored: boolean;
  is_encrypted?: boolean;
  encryption_algorithm?: string;
  encryption_iv?: string;
  encryption_salt?: string;
  original_filename?: string;
}

export interface FileUploadResponse {
  file_id: string;
  file_name: string;
  size: number;
  storage_url: string;
  message: string;
  encryption_algorithm?: string;
  encryption_iv?: string;
  encryption_salt?: string;
  is_encrypted?: boolean;
}

export interface FileListResponse {
  files: VaultFile[];
  folders: VaultFolder[];
  total_count: number;
}

export interface InitiateResumableUploadRequest {
  file_name: string;
  size: number;
  content_type: string;
  content_hash: string;
  encryption_algorithm: string;
  encryption_iv: string;
  encryption_salt: string;
  folder_id?: string;
}

export interface InitiateResumableUploadResponse {
  file_id: string;
  resumable_session_url: string;
  storage_location: 'gcs' | 's3' | 'local';
}

export interface ConfirmResumableUploadRequest {
  file_id: string;
  file_name: string;
  size: number;
  content_type: string;
  folder_id?: string;
  encryption_algorithm?: string;
  encryption_iv?: string;
  encryption_salt?: string;
}

export interface DownloadEncryptionInfo {
  algorithm: string;
  iv: string;
  salt: string;
  encrypted: boolean;
  zero_knowledge: boolean;
}

export interface InitiateProviderDownloadResponse {
  method: DownloadMethod;
  provider: StorageProvider;
  download_url: string | null;
  expires_at?: string | null;
  file_size_bytes: number;
  file_name: string;
  encryption: DownloadEncryptionInfo;
}

export interface RenameFileRequest {
  new_name: string;
}

export interface RenameFileResponse {
  id: string;
  name: string;
  size: number;
  content_type: string;
  created_at: string;
  modified_at?: string;
  created_by_user_id?: string;
  modified_by_user_id?: string;
}

// ============================================================================
// Folders
// ============================================================================

export interface VaultFolder {
  id: string;
  name: string;
  file_count: number;
  folder_count?: number;
  total_size: number;
  created_at?: string;
  source_type?: 'form_submission' | null;
  source_form_id?: string | null;
  source_submission_id?: string | null;
}

export interface CreateFolderRequest {
  name: string;
  parent_folder_id?: string;
}

export interface FolderResponse {
  id: string;
  name: string;
  file_count: number;
  total_size: number;
  message: string;
}

export interface RenameFolderRequest {
  new_name: string;
}

export interface RenameFolderResponse {
  id: string;
  name: string;
  file_count: number;
  total_size: number;
  created_by_user_id?: string;
  modified_by_user_id?: string;
}

// ============================================================================
// Security (encrypt / lock)
// ============================================================================

export interface EncryptVaultRequest {
  password: string;
}

export interface UnlockVaultRequest {
  password: string;
}

export interface VaultSecurityResponse {
  vault_id: string;
  is_encrypted: boolean;
  is_locked: boolean;
  message: string;
}

// ============================================================================
// Sharing
// ============================================================================

export interface VaultShare {
  share_id: string;
  vault_id: string;
  resource_type: string;
  resource_id: string;
  target_type: string;
  target_id: string;
  permission_level: string;
  can_reshare: boolean;
  expires_at?: string;
  shared_by_user_id: string;
  created_at: string;
  is_active: boolean;
}

export interface ShareVaultRequest {
  resource_type?: string;
  resource_id?: string;
  target_type: string;
  target_id: string;
  permission_level: string;
  can_reshare?: boolean;
  expires_in_days?: number;
}

export interface ShareResponse {
  share_id: string;
  vault_id: string;
  resource_type: string;
  resource_id: string;
  target_type: string;
  target_id: string;
  permission_level: string;
  can_reshare: boolean;
  expires_at?: string;
  is_active: boolean;
  message: string;
}

export interface ShareListResponse {
  shares: VaultShare[];
  total_count: number;
}

// ============================================================================
// Upload Links
// ============================================================================

export interface UploadLink {
  upload_link_id: string;
  vault_id: string;
  folder_id?: string;
  token: string;
  max_uploads?: number;
  upload_count: number;
  expires_at?: string;
  created_at: string;
  is_active: boolean;
  allowed_extensions?: string[] | null;
  max_file_size_bytes?: number | null;
  max_total_size_bytes?: number | null;
  allow_multiple_files?: boolean;
  has_ip_restriction?: boolean;
  has_email_otp_restriction?: boolean;
  has_account_restriction?: boolean;
  notification_emails?: string[] | null;
}

export interface CreateUploadLinkRequest {
  folder_id?: string;
  max_uploads?: number;
  expires_at?: string;
  allowed_extensions?: string[] | null;
  max_file_size_bytes?: number | null;
  max_total_size_bytes?: number | null;
  allow_multiple_files?: boolean;
  allowed_ips?: string[] | null;
  email_otp_restriction?: string[] | null;
  allowed_account_emails?: string[] | null;
  notification_emails?: string[] | null;
  message?: string;
}

export interface UploadLinkResponse {
  upload_link_id: string;
  vault_id: string;
  folder_id?: string;
  token: string;
  max_uploads?: number;
  upload_count: number;
  expires_at?: string;
  created_at: string;
  is_active: boolean;
  allowed_extensions?: string[] | null;
  max_file_size_bytes?: number | null;
  max_total_size_bytes?: number | null;
  allow_multiple_files?: boolean;
  vault_default_max_file_size?: number;
  org_storage_limit?: number;
  org_storage_used?: number;
  user_storage_limit?: number;
  user_storage_used?: number;
}

export interface UploadLinkListResponse {
  upload_links: UploadLink[];
  total_count: number;
}

// ============================================================================
// Public Branding
// ============================================================================

export interface PublicBranding {
  primary_color?: string;
  accent_color?: string;
  background_color?: string;
  surface_color?: string;
  text_primary_color?: string;
  text_secondary_color?: string;
  border_color?: string;
  custom_theme_json?: Record<string, string> | null;
  logo_light?: string;
  logo_url?: string;
  logo_dark?: string;
  logo_dark_url?: string;
  favicon?: string;
  app_name?: string;
  company_name?: string;
  tagline?: string;
  show_powered_by?: boolean;
  footer_text?: string;
  website_url?: string;
  terms_url?: string;
  privacy_url?: string;
  social_twitter?: string;
  social_linkedin?: string;
  social_facebook?: string;
  social_github?: string;
  public_share_headline?: string;
  public_share_description?: string;
  public_share_button_text?: string;
  public_share_features?: string[];
}

export interface SenderInfo {
  sender_name: string;
  sender_email: string;
  sender_organization: string;
}

export interface UploadLinkPublicInfo {
  vault_name: string;
  folder_id?: string;
  folder_name?: string;
  remaining_uploads?: number | null;
  expires_at?: string;
  allowed_extensions?: string[] | null;
  max_file_size_bytes?: number | null;
  max_total_size_bytes?: number | null;
  allow_multiple_files?: boolean;
  is_active?: boolean;
  available_storage_bytes?: number | null;
  allowed_mime_types?: string[] | null;
  requires_otp: boolean;
  requires_account: boolean;
  has_ip_restriction: boolean;
  message?: string;
  sender?: SenderInfo;
  branding?: PublicBranding;
}

export interface SendUploadOtpRequest {
  email: string;
}

export interface SendUploadOtpResponse {
  success: boolean;
  message: string;
  otp_expiry_minutes?: number;
}

export interface VerifyUploadOtpRequest {
  email: string;
  otp_code: string;
}

export interface VerifyUploadOtpResponse {
  success: boolean;
  message: string;
  session_token?: string;
  expires_in?: number;
}

// ============================================================================
// Storage / Quota
// ============================================================================

export interface StorageUsageResponse {
  used_bytes: number;
  quota_bytes: number;
  file_count: number;
  percentage_used: number;
}

export interface CheckStorageQuotaRequest {
  file_size: number;
}

export interface QuotaCheckResponse {
  can_upload: boolean;
  available_bytes: number;
  quota_bytes: number;
  used_bytes: number;
}

// ============================================================================
// Public Share Links
// ============================================================================

export type SecurityLevelType =
  | 'password_only'
  | 'password_otp'
  | 'account_login'
  | 'password_otp_account';

export interface PublicShareLink {
  link_id: string;
  vault_id: string;
  resource_type: 'file' | 'folder' | 'vault';
  resource_id: string;
  resource_name?: string;
  permission_level: 'download' | 'view';
  token: string;
  public_url: string;
  expires_at?: string;
  max_access_count?: number;
  access_count: number;
  remaining_accesses?: number;
  is_active: boolean;
  is_locked?: boolean;
  created_at: string;
  created_by_user_id: string;
  revoked_at?: string;
  message?: string;
  security_level_type?: SecurityLevelType;
  requires_password?: boolean;
  requires_otp?: boolean;
  requires_account?: boolean;
  allowed_user_ids?: string[];
  allowed_emails?: string[];
  allowed_ips?: string[];
  is_public?: boolean;
  auto_revoke_delay_seconds?: number | null;
  auto_delete_delay_seconds?: number | null;
  auto_revoke_scheduled_at?: string;
  auto_delete_scheduled_at?: string;
}

export interface CreatePublicShareLinkRequest {
  resource_type: 'file' | 'folder' | 'vault';
  resource_id: string;
  permission_level: 'download' | 'view';
  expires_in_days?: number;
  max_access_count?: number;
  message?: string;
  password_hash?: string;
  password_salt?: string;
  allowed_emails_otp?: string[];
  allowed_ips?: string[];
  require_account?: boolean;
  is_public?: boolean;
  notify_emails?: string;
  auto_revoke_delay_seconds?: number | null;
  auto_delete_delay_seconds?: number | null;
}

export interface PublicShareLinkResponse {
  link_id: string;
  token: string;
  public_url: string;
  vault_id: string;
  resource_type: 'file' | 'folder' | 'vault';
  resource_id: string;
  permission_level: 'download';
  expires_at?: string;
  max_access_count?: number;
  access_count: number;
  remaining_accesses?: number;
  is_active: boolean;
  created_by_user_id: string;
  created_at: string;
  message?: string;
  is_public?: boolean;
  auto_revoke_delay_seconds?: number | null;
  auto_delete_delay_seconds?: number | null;
  auto_revoke_scheduled_at?: string;
  auto_delete_scheduled_at?: string;
}

export interface PublicShareLinkListResponse {
  links: PublicShareLink[];
}

export interface PublicShareSecurity {
  has_email_otp_restriction: boolean;
  has_account_restriction: boolean;
}

export interface PublicAccessInfo {
  link_id: string;
  vault_id: string;
  resource_type: 'file' | 'folder' | 'vault';
  resource_id: string;
  permission_level: string;
  is_encrypted: boolean;
  remaining_accesses?: number;
  security?: {
    requires_password: boolean;
    password_salt: string;
    password_hash: string;
    has_email_otp_restriction: boolean;
    has_ip_restriction: boolean;
    has_account_restriction: boolean;
    is_hipaa_compliant: boolean;
    security_summary: string;
  };
  is_active?: boolean;
  is_locked?: boolean;
  expires_at?: string;
  next_step?: string;
  message?: string;
  sender?: SenderInfo;
  auto_revoke_delay_seconds?: number | null;
  auto_delete_delay_seconds?: number | null;
  auto_revoke_scheduled_at?: string;
  auto_delete_scheduled_at?: string;
}

export interface PublicShareContent {
  resource_type: 'file' | 'folder' | 'vault';
  message?: string;
  sender?: SenderInfo;
  branding?: PublicBranding;
  download_url?: string;
  files?: VaultFile[];
  file?: VaultFile;
  folder?: { id: string; name: string; file_count: number };
  vault?: { id: string; name: string; file_count: number };
  security?: PublicShareSecurity;
  is_locked?: boolean;
  is_active?: boolean;
  auto_revoke_delay_seconds?: number | null;
  auto_delete_delay_seconds?: number | null;
  auto_revoke_scheduled_at?: string;
  auto_delete_scheduled_at?: string;
}

// ============================================================================
// Share Link Authentication
// ============================================================================

export interface VerifyPasswordRequest {
  password: string;
}

export interface VerifyPasswordResponse {
  success: boolean;
  authenticated: boolean;
  requires_next_step?: boolean;
  next_step?: string;
  message?: string;
  attempts_remaining?: number;
  link_locked?: boolean;
}

export interface SendOTPRequest {
  email: string;
  name?: string;
}

export interface SendOTPResponse {
  success: boolean;
  message: string;
  otp_expiry_minutes?: number;
  otp_length?: number;
  max_attempts?: number;
  next_step?: string;
}

export interface VerifyOTPRequest {
  email: string;
  otp_code: string;
}

export interface VerifyOTPResponse {
  success: boolean;
  authenticated: boolean;
  requires_next_step?: boolean;
  next_step?: string;
  message?: string;
  access_token?: string;
  expires_in?: number;
  attempts_remaining?: number;
}

export interface VerifyIdentityRequest {
  name: string;
  email: string;
}

export interface VerifyIdentityResponse {
  success: boolean;
  authenticated: boolean;
  message: string;
  access_token?: string;
  expires_in?: number;
}

export interface AccessWithAccountResponse {
  success: boolean;
  authenticated: boolean;
  message: string;
  user_id?: string;
  access_token?: string;
  expires_in?: number;
}

// ============================================================================
// Audit Logs
// ============================================================================

export type AuditEventType =
  | 'link_created' | 'link_modified' | 'link_revoked' | 'link_expired'
  | 'link_view_attempt' | 'link_access_granted' | 'link_auth_success' | 'link_auth_failure'
  | 'password_verified' | 'password_incorrect'
  | 'otp_sent' | 'otp_verified' | 'otp_failed'
  | 'too_many_attempts' | 'link_locked'
  | 'account_login_success' | 'account_login_failure';

export interface AuditLog {
  id: string;
  share_link_id: string;
  event_type: AuditEventType;
  timestamp: string;
  created_by_user_id?: string | null;
  actor_email?: string | null;
  actor_name?: string | null;
  accessed_by_user_id?: string | null;
  accessor_email?: string | null;
  accessor_name?: string | null;
  verified_email?: string | null;
  verified_name?: string | null;
  ip_address?: string | null;
  user_agent?: string | null;
  geo_location?: string | null;
  success: boolean;
  failure_reason?: string | null;
  details?: Record<string, unknown> | null;
}

export interface AuditLogsResponse {
  total_count: number;
  logs: AuditLog[];
}

export interface SecurityEventsResponse {
  total_count: number;
  security_events: AuditLog[];
}

// ============================================================================
// Errors
// ============================================================================

export interface VaultError {
  error: string;
  error_type?: 'quota_exceeded' | 'vault_locked' | 'invalid_password';
  upgrade_required?: boolean;
}

// ============================================================================
// Utility Types & Type Guards
// ============================================================================

export type VaultStatus = 'active' | 'locked' | 'encrypted';
export type PermissionLevel = 'read' | 'write' | 'admin';
export type TargetType = 'user' | 'organization' | 'role';

export function isVaultError(error: unknown): error is VaultError {
  return typeof error === 'object' && error !== null && typeof (error as VaultError).error === 'string';
}

export function isVault(obj: unknown): obj is Vault {
  return (
    typeof obj === 'object' && obj !== null &&
    typeof (obj as Vault).id === 'string' &&
    typeof (obj as Vault).name === 'string' &&
    typeof (obj as Vault).is_encrypted === 'boolean'
  );
}

export function isVaultFile(obj: unknown): obj is VaultFile {
  return (
    typeof obj === 'object' && obj !== null &&
    typeof (obj as VaultFile).id === 'string' &&
    typeof (obj as VaultFile).name === 'string' &&
    typeof (obj as VaultFile).size === 'number'
  );
}

export function isVaultFolder(obj: unknown): obj is VaultFolder {
  return (
    typeof obj === 'object' && obj !== null &&
    typeof (obj as VaultFolder).id === 'string' &&
    typeof (obj as VaultFolder).name === 'string'
  );
}
