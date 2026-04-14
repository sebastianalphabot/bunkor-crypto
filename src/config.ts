/**
 * @bunkor/crypto - Configuration
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

/**
 * Bunkor API Configuration
 * Configure your Bunkor instance endpoints and credentials
 */
export interface BunkorConfig {
  /** Bunkor API base URL (e.g., https://api.bunkor.io or your self-hosted instance) */
  apiUrl: string;

  /** API authentication token */
  apiToken?: string;

  /** Organization ID or account identifier */
  organizationId?: string;

  /** Enable debug logging */
  debug?: boolean;

  /** Request timeout in milliseconds (default: 30000) */
  timeout?: number;

  /** Maximum file size for chunked upload in bytes (default: 5MB) */
  chunkSize?: number;
}

/**
 * Default Bunkor configuration
 * Override with your environment-specific settings
 */
export const DEFAULT_BUNKOR_CONFIG: Partial<BunkorConfig> = {
  apiUrl: process.env['BUNKOR_API_URL'] || 'https://api.bunkor.io',
  timeout: 30000,
  chunkSize: 5 * 1024 * 1024, // 5MB chunks
  debug: process.env['BUNKOR_DEBUG'] === 'true',
};

/**
 * Bunkor encryption defaults
 */
export const ENCRYPTION_DEFAULTS = {
  /** Default PBKDF2 iterations for password derivation (industry standard: 600K+) */
  PBKDF2_ITERATIONS: 600000,

  /** Default key length in bits (256 = 32 bytes) */
  KEY_LENGTH_BITS: 256,

  /** Default encryption algorithm (recommended: AES-256-GCM) */
  DEFAULT_ALGORITHM: 'AES-256-GCM' as const,

  /** Supported algorithms */
  SUPPORTED_ALGORITHMS: [
    'AES-256-GCM',      // Recommended: Fast, authenticated
    'AES-256-CBC',      // Legacy compatibility
    'AES-256-CTR',      // Stream cipher
    'Kyber-768-AES',    // Post-quantum hybrid (recommended for compliance)
    'Kyber-1024-AES',   // Post-quantum hybrid (highest security)
  ] as const,

  /** IV sizes by algorithm (in bytes) */
  IV_SIZES: {
    'AES-256-GCM': 12,
    'AES-256-CBC': 16,
    'AES-256-CTR': 16,
    'Kyber-768-AES': 12,
    'Kyber-1024-AES': 12,
  } as const,

  /** Encryption overhead by algorithm (in bytes) */
  OVERHEAD: {
    'AES-256-GCM': 16,                  // Authentication tag
    'AES-256-CBC': 16,                  // PKCS#7 padding
    'AES-256-CTR': 0,                   // No overhead
    'Kyber-768-AES': 1088 + 16,         // KEM ciphertext + tag
    'Kyber-1024-AES': 1568 + 16,        // KEM ciphertext + tag
  } as const,
};

/**
 * Bunkor API endpoints
 */
export const BUNKOR_ENDPOINTS = {
  /** File upload endpoint */
  UPLOAD: '/v1/files/upload',

  /** File download endpoint */
  DOWNLOAD: '/v1/files/:fileId/download',

  /** Get file metadata */
  GET_FILE: '/v1/files/:fileId',

  /** List files */
  LIST_FILES: '/v1/files',

  /** Delete file */
  DELETE_FILE: '/v1/files/:fileId',

  /** Share file access */
  SHARE: '/v1/files/:fileId/share',

  /** Get share link */
  GET_SHARE: '/v1/shares/:shareId',

  /** Audit log */
  AUDIT_LOG: '/v1/files/:fileId/audit',

  /** Key management */
  KEYS: '/v1/keys',
  GET_KEY: '/v1/keys/:keyId',
  WRAP_KEY: '/v1/keys/wrap',
  UNWRAP_KEY: '/v1/keys/unwrap',

  /** Health check */
  HEALTH: '/v1/health',
} as const;

/**
 * Security guidelines
 */
export const SECURITY_GUIDELINES = {
  /**
   * Minimum password strength requirements
   */
  PASSWORD: {
    MIN_LENGTH: 8,
    REQUIRE_UPPERCASE: true,
    REQUIRE_LOWERCASE: true,
    REQUIRE_NUMBERS: true,
    REQUIRE_SPECIAL_CHARS: true,
    RECOMMENDED_LENGTH: 12,
  },

  /**
   * Key management best practices
   */
  KEY_MANAGEMENT: {
    NEVER_LOG_KEYS: true,
    NEVER_STORE_PLAINTEXT_KEYS: true,
    USE_SECURE_STORAGE: true,
    ROTATE_KEYS_PERIODICALLY: true,
    ROTATION_INTERVAL_DAYS: 90,
  },

  /**
   * File encryption best practices
   */
  FILE_ENCRYPTION: {
    USE_AES_GCM: true,
    GENERATE_UNIQUE_IV: true,
    VERIFY_AUTHENTICATION_TAG: true,
    USE_STRONG_PASSWORDS: true,
  },
};
