/**
 * @bunkor/crypto - Zero-knowledge cryptographic utilities
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// ============================================================================
// Core Crypto Services
// ============================================================================
export { CryptoService } from './crypto.service';
export { EncryptionService } from './encryption.service';
export type { EncryptionAlgorithm, EncryptionResult, DecryptionParams } from './encryption.service';
export { SecureFormCryptoService } from './secure-form-crypto.service';
export { KeyringEncryptionService } from './keyring-encryption.service';

// ============================================================================
// Encryption Strategies
// ============================================================================
export type { IEncryptionStrategy } from './encryption/encryption-strategy.interface';

// ============================================================================
// Models & Types
// ============================================================================
export type { EncFileJson, KdfParams } from './models/secure-forms.models';

// Vault domain models
export type {
  Vault, CreateVaultRequest, CreateVaultResponse, ListVaultsResponse,
  RenameVaultRequest, RenameVaultResponse,
  VaultFile, FileListResponse, FileUploadResponse,
  InitiateResumableUploadRequest, InitiateResumableUploadResponse,
  ConfirmResumableUploadRequest, InitiateProviderDownloadResponse,
  DownloadEncryptionInfo,
  RenameFileRequest, RenameFileResponse,
  VaultFolder, CreateFolderRequest, FolderResponse,
  RenameFolderRequest, RenameFolderResponse,
  EncryptVaultRequest, UnlockVaultRequest, VaultSecurityResponse,
  VaultShare, ShareVaultRequest, ShareResponse, ShareListResponse,
  UploadLink, CreateUploadLinkRequest, UploadLinkResponse, UploadLinkListResponse,
  UploadLinkPublicInfo, SendUploadOtpRequest, SendUploadOtpResponse,
  VerifyUploadOtpRequest, VerifyUploadOtpResponse,
  StorageUsageResponse, CheckStorageQuotaRequest, QuotaCheckResponse,
  PublicBranding, SenderInfo,
  SecurityLevelType, PublicShareLink, CreatePublicShareLinkRequest,
  PublicShareLinkResponse, PublicShareLinkListResponse, PublicShareSecurity,
  PublicAccessInfo, PublicShareContent,
  VerifyPasswordRequest, VerifyPasswordResponse,
  SendOTPRequest, SendOTPResponse, VerifyOTPRequest, VerifyOTPResponse,
  VerifyIdentityRequest, VerifyIdentityResponse, AccessWithAccountResponse,
  AuditEventType, AuditLog, AuditLogsResponse, SecurityEventsResponse,
  VaultError, VaultStatus, PermissionLevel, TargetType, StorageProvider, DownloadMethod,
} from './models/vault.models';
export { isVaultError, isVault, isVaultFile, isVaultFolder, PROVIDER_DOWNLOAD_THRESHOLD_BYTES } from './models/vault.models';

// Secure Email domain models
export { EmailStatus } from './models/email.models';
export type {
  SecureEmailAttachment,
  CreateDraftRequest, CreateDraftResponse, UpdateDraftRequest, UpdateDraftResponse, SendDraftResponse,
  CreateSecureEmailRequest, CreateSecureEmailResponse,
  EmailRecipient, AccessSecureEmailResponse,
  DraftSecureEmail, DraftsEmailsResponse,
  SentSecureEmail, SentEmailsResponse,
  InboxSecureEmail, InboxEmailsResponse,
  TrashSecureEmail, TrashEmailsResponse,
  EmailDetailResponse, EmailActionResponse, MarkReadResponse, UnreadCountResponse,
  AddAttachmentRequest, AddAttachmentResponse,
  InitiateAttachmentUploadRequest, InitiateAttachmentUploadResponse,
  ConfirmAttachmentUploadRequest, ConfirmAttachmentUploadResponse,
  AttachVaultFileRequest, AttachVaultFileResponse,
  EmailPaginationParams,
} from './models/email.models';

// ============================================================================
// Configuration
// ============================================================================
export type { BunkorConfig } from './config';
export { DEFAULT_BUNKOR_CONFIG, ENCRYPTION_DEFAULTS, BUNKOR_ENDPOINTS, SECURITY_GUIDELINES } from './config';

// ============================================================================
// Bunkor Integration Client (generic file upload/download)
// ============================================================================
export { BunkorClient } from './utils/bunkor-client';
export type { BunkorUploadResponse, BunkorFileMetadata } from './utils/bunkor-client';

// ============================================================================
// Domain API Clients  (Repository pattern — framework-agnostic, fetch-based)
// ============================================================================
export { VaultClient } from './clients/vault.client';
export { SecureFormsClient } from './clients/secure-forms.client';
export { SecureEmailClient } from './clients/secure-email.client';

// HTTP transport primitives (extend BaseClient to build your own domain client)
export { BaseClient, BunkorApiError } from './clients/base.client';
export type { ResolvedConfig } from './clients/base.client';

// ============================================================================
// Cryptographic Utilities
// ============================================================================
export {
  generateRandomString,
  generateRandomHex,
  arrayBufferToBase64,
  base64ToArrayBuffer,
  arrayBufferToHex,
  hexToArrayBuffer,
  sha256,
  validatePassword,
  calculatePasswordStrength,
  formatBytes,
  deriveKeyFromSeed,
  secureCompare,
  clearSensitiveData,
  isWebCryptoAvailable,
  checkEncryptionSupport,
  getEncryptionCapabilities,
} from './utils/crypto-utils';
