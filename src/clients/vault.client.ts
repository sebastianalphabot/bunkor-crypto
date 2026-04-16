/**
 * @bunkor/crypto — VaultClient
 *
 * Repository-pattern client for all Vault, File, Folder, Sharing, Upload Link,
 * Public Share, and Audit Log operations.
 *
 * Design patterns:
 *   - Repository: clean CRUD interface over the Bunkor Vault API
 *   - Template Method: inherits auth + error handling from BaseClient
 *
 * Usage:
 * ```ts
 * const vault = new VaultClient({ apiUrl: 'https://lockbox-app-…', apiToken: 'sk_…' });
 * const list  = await vault.listVaults();
 * const files = await vault.listFiles(vaultId);
 * ```
 *
 * Licensed under the Apache License, Version 2.0
 */

import { BunkorConfig } from '../config';
import { BaseClient } from './base.client';
import {
  Vault, CreateVaultRequest, CreateVaultResponse, ListVaultsResponse,
  RenameVaultRequest, RenameVaultResponse,
  VaultFile, FileListResponse, FileUploadResponse,
  InitiateResumableUploadRequest, InitiateResumableUploadResponse,
  ConfirmResumableUploadRequest, InitiateProviderDownloadResponse,
  RenameFileRequest, RenameFileResponse,
  VaultFolder, CreateFolderRequest, FolderResponse, RenameFolderRequest, RenameFolderResponse,
  EncryptVaultRequest, UnlockVaultRequest, VaultSecurityResponse,
  ShareVaultRequest, ShareResponse, ShareListResponse,
  CreateUploadLinkRequest, UploadLinkResponse, UploadLinkListResponse,
  UploadLinkPublicInfo, SendUploadOtpRequest, SendUploadOtpResponse,
  VerifyUploadOtpRequest, VerifyUploadOtpResponse,
  StorageUsageResponse, CheckStorageQuotaRequest, QuotaCheckResponse,
  CreatePublicShareLinkRequest, PublicShareLinkResponse, PublicShareLinkListResponse,
  PublicAccessInfo, PublicShareContent,
  VerifyPasswordRequest, VerifyPasswordResponse,
  SendOTPRequest, SendOTPResponse, VerifyOTPRequest, VerifyOTPResponse,
  VerifyIdentityRequest, VerifyIdentityResponse,
  AuditLogsResponse, SecurityEventsResponse,
} from '../models/vault.models';

// Re-export the server base URL constant so consumers don't need the config import.
export { DEFAULT_BUNKOR_CONFIG } from '../config';

export class VaultClient extends BaseClient {
  private readonly base = '/api/v1/vaults';

  constructor(config: BunkorConfig) {
    super(config);
  }

  // ─── Vault Lifecycle ──────────────────────────────────────────────────────

  /** List all vaults for the authenticated organisation. */
  listVaults(): Promise<ListVaultsResponse> {
    return this.get<ListVaultsResponse>(`${this.base}/`);
  }

  /** Create a new vault. */
  createVault(request: CreateVaultRequest): Promise<CreateVaultResponse> {
    return this.post<CreateVaultResponse>(`${this.base}/`, request);
  }

  /** Get a single vault by ID. */
  getVault(vaultId: string): Promise<Vault> {
    return this.get<Vault>(`${this.base}/${vaultId}/`);
  }

  /** Rename a vault. */
  renameVault(vaultId: string, request: RenameVaultRequest): Promise<RenameVaultResponse> {
    return this.patch<RenameVaultResponse>(`${this.base}/${vaultId}/rename/`, request);
  }

  /** Delete a vault. */
  deleteVault(vaultId: string): Promise<void> {
    return this.delete<void>(`${this.base}/${vaultId}/`);
  }

  // ─── Files ────────────────────────────────────────────────────────────────

  /** List files and folders inside a vault (optionally scoped to a folder). */
  listFiles(vaultId: string, folderId?: string): Promise<FileListResponse> {
    const params: Record<string, string> = {};
    if (folderId) params['folder_id'] = folderId;
    return this.get<FileListResponse>(`${this.base}/${vaultId}/files/`, params);
  }

  /**
   * Upload a file to the vault (multipart/form-data).
   *
   * For large files use `initiateResumableUpload` + `confirmResumableUpload`
   * with direct provider upload instead.
   */
  uploadFile(
    vaultId: string,
    file: Blob,
    fileName: string,
    options?: {
      folderId?: string;
      encryptionAlgorithm?: string;
      encryptionIv?: string;
      encryptionSalt?: string;
      originalFilename?: string;
    },
  ): Promise<FileUploadResponse> {
    const form = new FormData();
    form.append('file', file, fileName);
    if (options?.folderId)            form.append('folder_id', options.folderId);
    if (options?.encryptionAlgorithm) form.append('encryption_algorithm', options.encryptionAlgorithm);
    if (options?.encryptionIv)        form.append('encryption_iv', options.encryptionIv);
    if (options?.encryptionSalt)      form.append('encryption_salt', options.encryptionSalt);
    if (options?.originalFilename)    form.append('original_filename', options.originalFilename);
    return this.postForm<FileUploadResponse>(`${this.base}/${vaultId}/files/upload/`, form);
  }

  /** Begin a resumable (chunked) upload. Returns a session URL for direct-to-provider upload. */
  initiateResumableUpload(
    vaultId: string,
    request: InitiateResumableUploadRequest,
  ): Promise<InitiateResumableUploadResponse> {
    return this.post<InitiateResumableUploadResponse>(
      `${this.base}/${vaultId}/files/initiate-upload/`,
      request,
    );
  }

  /** Confirm that the resumable upload has finished and register the file in Bunkor. */
  confirmResumableUpload(
    vaultId: string,
    request: ConfirmResumableUploadRequest,
  ): Promise<FileUploadResponse> {
    return this.post<FileUploadResponse>(
      `${this.base}/${vaultId}/files/confirm-upload/`,
      request,
    );
  }

  /** Get a provider-signed download URL for a file. */
  initiateDownload(vaultId: string, fileId: string): Promise<InitiateProviderDownloadResponse> {
    return this.post<InitiateProviderDownloadResponse>(
      `${this.base}/${vaultId}/files/${fileId}/initiate-download/`,
    );
  }

  /** Delete a file. */
  deleteFile(vaultId: string, fileId: string): Promise<void> {
    return this.delete<void>(`${this.base}/${vaultId}/files/${fileId}/`);
  }

  /** Rename a file. */
  renameFile(
    vaultId: string,
    fileId: string,
    request: RenameFileRequest,
  ): Promise<RenameFileResponse> {
    return this.patch<RenameFileResponse>(`${this.base}/${vaultId}/files/${fileId}/rename/`, request);
  }

  // ─── Folders ──────────────────────────────────────────────────────────────

  /** Create a folder inside a vault. */
  createFolder(vaultId: string, request: CreateFolderRequest): Promise<FolderResponse> {
    return this.post<FolderResponse>(`${this.base}/${vaultId}/folders/`, request);
  }

  /** Get folder metadata. */
  getFolder(vaultId: string, folderId: string): Promise<VaultFolder> {
    return this.get<VaultFolder>(`${this.base}/${vaultId}/folders/${folderId}/`);
  }

  /** Rename a folder. */
  renameFolder(
    vaultId: string,
    folderId: string,
    request: RenameFolderRequest,
  ): Promise<RenameFolderResponse> {
    return this.patch<RenameFolderResponse>(
      `${this.base}/${vaultId}/folders/${folderId}/rename/`,
      request,
    );
  }

  /** Delete a folder and all its contents. */
  deleteFolder(vaultId: string, folderId: string): Promise<void> {
    return this.delete<void>(`${this.base}/${vaultId}/folders/${folderId}/`);
  }

  // ─── Vault Security ───────────────────────────────────────────────────────

  /** Enable password encryption on a vault. */
  encryptVault(vaultId: string, request: EncryptVaultRequest): Promise<VaultSecurityResponse> {
    return this.post<VaultSecurityResponse>(`${this.base}/${vaultId}/encrypt/`, request);
  }

  /** Unlock an encrypted vault for the session. */
  unlockVault(vaultId: string, request: UnlockVaultRequest): Promise<VaultSecurityResponse> {
    return this.post<VaultSecurityResponse>(`${this.base}/${vaultId}/unlock/`, request);
  }

  // ─── Sharing ──────────────────────────────────────────────────────────────

  /** Share a vault (or specific resource within it) with a user / group. */
  shareVault(vaultId: string, request: ShareVaultRequest): Promise<ShareResponse> {
    return this.post<ShareResponse>(`${this.base}/${vaultId}/share/`, request);
  }

  /** List active shares for a vault. */
  listShares(vaultId: string): Promise<ShareListResponse> {
    return this.get<ShareListResponse>(`${this.base}/${vaultId}/shares/`);
  }

  /** Remove a share. */
  removeShare(vaultId: string, shareId: string): Promise<void> {
    return this.delete<void>(`${this.base}/${vaultId}/shares/${shareId}/`);
  }

  // ─── Upload Links ─────────────────────────────────────────────────────────

  /** Create an upload link that lets external users upload to this vault. */
  createUploadLink(
    vaultId: string,
    request: CreateUploadLinkRequest,
  ): Promise<UploadLinkResponse> {
    return this.post<UploadLinkResponse>(`${this.base}/${vaultId}/upload-links/`, request);
  }

  /** List upload links for a vault. */
  listUploadLinks(vaultId: string): Promise<UploadLinkListResponse> {
    return this.get<UploadLinkListResponse>(`${this.base}/${vaultId}/upload-links/`);
  }

  /** Deactivate an upload link. */
  deleteUploadLink(vaultId: string, uploadLinkId: string): Promise<void> {
    return this.delete<void>(`${this.base}/${vaultId}/upload-links/${uploadLinkId}/`);
  }

  // ─── Upload Link — Public (no auth required) ──────────────────────────────

  /** Fetch metadata for a public upload link (shown before upload). */
  getUploadLinkPublicInfo(token: string): Promise<UploadLinkPublicInfo> {
    return this.get<UploadLinkPublicInfo>(`/api/v1/upload/${token}/info/`);
  }

  /** Send OTP to the uploader's email for identity verification. */
  sendUploadOtp(token: string, request: SendUploadOtpRequest): Promise<SendUploadOtpResponse> {
    return this.post<SendUploadOtpResponse>(`/api/v1/upload/${token}/send-otp/`, request);
  }

  /** Verify OTP code and receive a session token. */
  verifyUploadOtp(token: string, request: VerifyUploadOtpRequest): Promise<VerifyUploadOtpResponse> {
    return this.post<VerifyUploadOtpResponse>(`/api/v1/upload/${token}/verify-otp/`, request);
  }

  // ─── Storage / Quota ──────────────────────────────────────────────────────

  /** Get storage usage statistics. */
  getStorageUsage(): Promise<StorageUsageResponse> {
    return this.get<StorageUsageResponse>('/api/v1/storage/usage/');
  }

  /** Pre-flight check: can the user upload a file of the given size? */
  checkStorageQuota(request: CheckStorageQuotaRequest): Promise<QuotaCheckResponse> {
    return this.post<QuotaCheckResponse>('/api/v1/storage/check-quota/', request);
  }

  // ─── Public Share Links ───────────────────────────────────────────────────

  /** Create a public (password-protected) share link for a resource. */
  createShareLink(
    vaultId: string,
    request: CreatePublicShareLinkRequest,
  ): Promise<PublicShareLinkResponse> {
    return this.post<PublicShareLinkResponse>(`${this.base}/${vaultId}/share-links/`, request);
  }

  /** List share links for a vault. */
  listShareLinks(vaultId: string): Promise<PublicShareLinkListResponse> {
    return this.get<PublicShareLinkListResponse>(`${this.base}/${vaultId}/share-links/`);
  }

  /** Revoke a share link. */
  revokeShareLink(vaultId: string, linkId: string): Promise<void> {
    return this.delete<void>(`${this.base}/${vaultId}/share-links/${linkId}/`);
  }

  // ─── Public Share — unauthenticated access flow ───────────────────────────

  /** Get public info about a share link (before authentication). */
  getPublicAccessInfo(token: string): Promise<PublicAccessInfo> {
    return this.get<PublicAccessInfo>(`/api/v1/share/${token}/`);
  }

  /** Verify the share link password (zero-knowledge — only the hash is sent). */
  verifySharePassword(
    token: string,
    request: VerifyPasswordRequest,
  ): Promise<VerifyPasswordResponse> {
    return this.post<VerifyPasswordResponse>(`/api/v1/share/${token}/verify-password/`, request);
  }

  /** Send OTP to a whitelisted email for share link access. */
  sendShareOtp(token: string, request: SendOTPRequest): Promise<SendOTPResponse> {
    return this.post<SendOTPResponse>(`/api/v1/share/${token}/send-otp/`, request);
  }

  /** Verify the share OTP. */
  verifyShareOtp(token: string, request: VerifyOTPRequest): Promise<VerifyOTPResponse> {
    return this.post<VerifyOTPResponse>(`/api/v1/share/${token}/verify-otp/`, request);
  }

  /** Verify identity (name + email) for account-restricted share links. */
  verifyShareIdentity(
    token: string,
    request: VerifyIdentityRequest,
  ): Promise<VerifyIdentityResponse> {
    return this.post<VerifyIdentityResponse>(`/api/v1/share/${token}/verify-identity/`, request);
  }

  /** Fetch the decrypted content (files / folder listing) for a share link. */
  getPublicShareContent(token: string, accessToken?: string): Promise<PublicShareContent> {
    const params = accessToken ? { access_token: accessToken } : undefined;
    return this.get<PublicShareContent>(`/api/v1/share/${token}/content/`, params);
  }

  // ─── Audit Logs ───────────────────────────────────────────────────────────

  /** Retrieve the audit log for a share link. */
  getAuditLogs(
    vaultId: string,
    linkId: string,
    params?: { page?: number; page_size?: number },
  ): Promise<AuditLogsResponse> {
    return this.get<AuditLogsResponse>(
      `${this.base}/${vaultId}/share-links/${linkId}/audit-logs/`,
      params,
    );
  }

  /** Retrieve security events for a share link. */
  getSecurityEvents(
    vaultId: string,
    linkId: string,
    params?: { page?: number; page_size?: number },
  ): Promise<SecurityEventsResponse> {
    return this.get<SecurityEventsResponse>(
      `${this.base}/${vaultId}/share-links/${linkId}/security-events/`,
      params,
    );
  }
}
