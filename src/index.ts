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
export {
  EncryptionService,
  EncryptionAlgorithm,
  EncryptionResult,
  DecryptionParams,
} from './encryption.service';
export { SecureFormCryptoService } from './secure-form-crypto.service';
export { KeyringEncryptionService } from './keyring-encryption.service';

// ============================================================================
// Encryption Strategies
// ============================================================================
export { EncryptionStrategy } from './encryption/encryption-strategy.interface';

// ============================================================================
// Models & Types
// ============================================================================
export type { EncFileJson, KdfParams } from './models/secure-forms.models';

// ============================================================================
// Configuration
// ============================================================================
export {
  BunkorConfig,
  DEFAULT_BUNKOR_CONFIG,
  ENCRYPTION_DEFAULTS,
  BUNKOR_ENDPOINTS,
  SECURITY_GUIDELINES,
} from './config';

// ============================================================================
// Bunkor Integration Client
// ============================================================================
export { BunkorClient } from './utils/bunkor-client';
export type { BunkorUploadResponse, BunkorFileMetadata } from './utils/bunkor-client';

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
