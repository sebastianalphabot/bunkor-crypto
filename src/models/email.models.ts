/**
 * @bunkor/crypto — Secure Email Domain Models
 *
 * Pure TypeScript models for all secure email API operations.
 * No Angular or framework dependencies.
 *
 * Based on Secure Email API Guide v2.0
 *
 * Licensed under the Apache License, Version 2.0
 */

import type { PublicBranding } from './vault.models';

// ============================================================================
// Enums
// ============================================================================

export enum EmailStatus {
  DRAFT = 'DRAFT',
  SENT  = 'SENT',
  TRASH = 'TRASH',
}

// ============================================================================
// Attachments
// ============================================================================

export interface SecureEmailAttachment {
  attachment_id: string;
  filename: string;
  content_type: string;
  encrypted_size_bytes: number;
  storage_url?: string;
  is_vault_reference?: boolean;
  source_vault_id?: string;
  source_vault_file_id?: string;
  wrapped_file_key?: string;
  wrapped_file_key_iv?: string;
  vault_file_iv?: string;
  checksum?: string;
  iv?: string;
  encryption_algorithm?: string;
}

// ============================================================================
// Draft Lifecycle
// ============================================================================

export interface CreateDraftRequest {
  subject?: string;
  recipients?: string[];
  encrypted_content?: string;
  encryption_algorithm?: string;
  iv?: string;
  salt?: string;
  iterations?: number;
  requires_authentication?: boolean;
  reply_to_email_id?: string;
}

export interface CreateDraftResponse {
  email_id: string;
  access_token: string;
  access_link: string;
  subject: string;
  created_at: string;
  message: string;
}

export interface UpdateDraftRequest {
  subject?: string;
  recipients?: string[];
  encrypted_content?: string;
  encryption_algorithm?: string;
  iv?: string;
  salt?: string;
  iterations?: number;
}

export interface UpdateDraftResponse {
  message: string;
}

export interface SendDraftResponse {
  message: string;
}

// ============================================================================
// Create & Send (legacy flow)
// ============================================================================

export interface CreateSecureEmailRequest {
  subject: string;
  recipients: string[];
  encrypted_content: string;
  encryption_algorithm: string;
  iv: string;
  salt: string;
  iterations: number;
  requires_authentication: boolean;
  send_email_notification: boolean;
  expiration_time?: string;
  max_access_count?: number;
  reply_to_email_id?: string;
  is_public?: boolean;
  status?: string;
}

export interface CreateSecureEmailResponse {
  email_id: string;
  access_token: string;
  access_link: string;
  subject: string;
  created_at: string;
  requires_authentication: boolean;
  send_email_notification: boolean;
  expires_at: string;
  max_access_count: number;
  reply_to_email_id?: string;
  is_public: boolean;
  message: string;
}

// ============================================================================
// Access (public endpoint)
// ============================================================================

export interface EmailRecipient {
  email_address: string;
  has_accessed: boolean;
  accessed_at?: string;
  is_read?: boolean;
}

export interface AccessSecureEmailResponse {
  email_id: string;
  subject: string;
  sender_email: string;
  sender_name: string;
  organization_name?: string;
  recipients: EmailRecipient[];
  encrypted_content: string;
  encryption_algorithm: string;
  iv: string;
  salt: string;
  iterations: number;
  attachments: SecureEmailAttachment[];
  created_at: string;
  access_count: number;
  expires_at: string;
  max_access_count: number;
  is_expired: boolean;
  requires_authentication: boolean;
  is_public?: boolean;
  reply_to_email_id?: string;
  branding?: PublicBranding;
}

// ============================================================================
// Listings — Drafts / Sent / Inbox / Trash
// ============================================================================

export interface DraftSecureEmail {
  email_id: string;
  subject: string;
  recipient_emails: string[];
  recipient_count: number;
  created_at: string;
  has_attachments: boolean;
  attachment_count: number;
  status: EmailStatus;
  requires_authentication?: boolean;
  is_public?: boolean;
  access_token: string;
  reply_to_email_id?: string;
}

export interface DraftsEmailsResponse {
  emails: DraftSecureEmail[];
  total_count: number;
  page: number;
  page_size: number;
  total_pages: number;
}

export interface SentSecureEmail {
  email_id: string;
  subject: string;
  recipient_emails: string[];
  recipient_count: number;
  created_at: string;
  access_count: number;
  has_attachments: boolean;
  attachment_count: number;
  is_expired: boolean;
  expires_at?: string | null;
  max_access_count?: number | null;
  status: EmailStatus;
  is_read: boolean;
  requires_authentication: boolean;
  is_public?: boolean;
  access_token: string;
  reply_to_email_id?: string;
}

export interface SentEmailsResponse {
  emails: SentSecureEmail[];
  total_count: number;
  page: number;
  page_size: number;
  total_pages: number;
  filter_expired: boolean | null;
}

export interface InboxSecureEmail {
  email_id: string;
  subject: string;
  sender_email: string;
  sender_name: string;
  organization_name?: string;
  recipient_emails: string[];
  recipient_count: number;
  created_at: string;
  access_count: number;
  has_attachments: boolean;
  attachment_count: number;
  is_expired: boolean;
  expires_at?: string | null;
  max_access_count?: number | null;
  status: EmailStatus;
  is_read: boolean;
  has_accessed: boolean;
  accessed_at?: string;
  requires_authentication: boolean;
  is_public?: boolean;
  access_token: string;
  reply_to_email_id?: string;
}

export interface InboxEmailsResponse {
  emails: InboxSecureEmail[];
  total_count: number;
  page: number;
  page_size: number;
  total_pages: number;
  filter_expired: boolean | null;
}

export interface TrashSecureEmail {
  email_id: string;
  subject: string;
  recipient_emails: string[];
  recipient_count: number;
  created_at: string;
  has_attachments: boolean;
  attachment_count: number;
  is_expired: boolean;
  status: EmailStatus;
  requires_authentication?: boolean;
  is_public?: boolean;
  access_token: string;
  reply_to_email_id?: string;
}

export interface TrashEmailsResponse {
  emails: TrashSecureEmail[];
  total_count: number;
  page: number;
  page_size: number;
  total_pages: number;
}

// ============================================================================
// Email Detail & Actions
// ============================================================================

export interface EmailDetailResponse {
  email_id: string;
  subject: string;
  status: EmailStatus;
  recipients: EmailRecipient[];
  encrypted_content: string;
  encryption_metadata: {
    algorithm: string;
    iv: string;
    salt: string;
    iterations: number;
  };
  attachments: SecureEmailAttachment[];
  created_at: string;
  access_count: number;
  is_expired: boolean;
  requires_authentication: boolean;
  is_public?: boolean;
  access_token: string;
  reply_to_email_id?: string;
}

export interface EmailActionResponse {
  message: string;
}

export interface MarkReadResponse {
  message: string;
}

export interface UnreadCountResponse {
  unread_count: number;
}

// ============================================================================
// Attachments — Upload & Vault Attach
// ============================================================================

export interface AddAttachmentRequest {
  filename: string;
  content_type: string;
  encrypted_size_bytes: number;
  storage_url: string;
  checksum: string;
  iv: string;
  encryption_algorithm: string;
}

export interface AddAttachmentResponse {
  attachment_id: string;
  filename: string;
  storage_url: string;
  message: string;
}

export interface InitiateAttachmentUploadRequest {
  file_name: string;
  size: number;
  content_type: string;
  content_hash?: string;
}

export interface InitiateAttachmentUploadResponse {
  attachment_id: string;
  resumable_session_url: string;
  email_id: string;
  message: string;
}

export interface ConfirmAttachmentUploadRequest {
  attachment_id: string;
  file_name: string;
  size: number;
  content_type: string;
  checksum: string;
  iv: string;
  encryption_algorithm?: string;
}

export interface ConfirmAttachmentUploadResponse {
  attachment_id: string;
  email_id: string;
  filename: string;
  content_type: string;
  encrypted_size_bytes: number;
  storage_url: string;
  message: string;
}

export interface AttachVaultFileRequest {
  vault_id: string;
  file_id: string;
  wrapped_file_key: string;
  iv: string;
  vault_file_iv: string;
}

export interface AttachVaultFileResponse {
  attachment_id: string;
  email_id: string;
  filename: string;
  content_type: string;
  encrypted_size_bytes: number;
  storage_url: string;
  source_vault_id?: string;
  source_vault_file_id?: string;
  wrapped_file_key?: string;
  iv?: string;
  is_vault_reference?: boolean;
  message: string;
}

// ============================================================================
// Pagination helpers
// ============================================================================

export interface EmailPaginationParams {
  page?: number;
  page_size?: number;
  filter_expired?: boolean;
}
