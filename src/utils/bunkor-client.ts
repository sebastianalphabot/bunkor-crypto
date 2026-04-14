/**
 * @bunkor/crypto - Bunkor Integration Client
 *
 * Utilities for uploading/downloading encrypted files to Bunkor
 */

import { EncryptionService, EncryptionAlgorithm } from '../encryption.service';
import { CryptoService } from '../crypto.service';
import { BunkorConfig, BUNKOR_ENDPOINTS, DEFAULT_BUNKOR_CONFIG } from '../config';

/**
 * File upload response from Bunkor
 */
export interface BunkorUploadResponse {
  fileId: string;
  fileName: string;
  size: number;
  checksum: string;
  encryptionAlgorithm: EncryptionAlgorithm;
  salt: string;
  iv: string;
  uploadedAt: string;
  expiresAt?: string;
}

/**
 * File download metadata from Bunkor
 */
export interface BunkorFileMetadata {
  fileId: string;
  fileName: string;
  size: number;
  encryptionAlgorithm: EncryptionAlgorithm;
  salt: string;
  iv: string;
  createdAt: string;
  updatedAt: string;
  ownerId: string;
  isShared: boolean;
}

/**
 * Bunkor Client - Handle encrypted file operations with Bunkor
 */
export class BunkorClient {
  private config: Required<BunkorConfig>;
  private encryptionService: EncryptionService;
  private cryptoService: CryptoService;

  constructor(config: BunkorConfig) {
    this.config = {
      ...DEFAULT_BUNKOR_CONFIG,
      ...config,
    } as Required<BunkorConfig>;

    this.encryptionService = new EncryptionService();
    this.cryptoService = new CryptoService();
  }

  /**
   * Upload and encrypt a file to Bunkor
   *
   * @param file File to upload
   * @param password Encryption password
   * @param algorithm Encryption algorithm (default: AES-256-GCM)
   * @param fileName Optional custom file name
   * @returns Upload response with file ID and encryption metadata
   *
   * @example
   * ```typescript
   * const client = new BunkorClient({
   *   apiUrl: 'https://api.bunkor.io',
   *   apiToken: 'sk_live_...',
   * });
   *
   * const response = await client.uploadEncrypted(
   *   file,
   *   'secure-password',
   *   'AES-256-GCM',
   *   'my-document.pdf'
   * );
   *
   * console.log(response.fileId); // Store this for later download
   * ```
   */
  async uploadEncrypted(
    file: File | Blob,
    password: string,
    algorithm: EncryptionAlgorithm = 'AES-256-GCM',
    fileName?: string
  ): Promise<BunkorUploadResponse> {
    try {
      // Generate salt and IV
      const salt = this.cryptoService.generateSalt();
      const iv = this.generateIv(algorithm);

      // Encrypt file
      const encrypted = await this.encryptionService.encryptFile({
        file,
        password,
        algorithm,
        salt,
        iv,
      });

      // Prepare FormData for upload
      const formData = new FormData();
      formData.append('file', encrypted.encryptedBlob, fileName || 'encrypted-file');
      formData.append('algorithm', algorithm);
      formData.append('salt', salt);
      formData.append('iv', iv);
      formData.append('checksum', await this.calculateChecksum(encrypted.encryptedBlob));

      // Upload to Bunkor
      const response = await this.fetchBunkor(BUNKOR_ENDPOINTS.UPLOAD, {
        method: 'POST',
        body: formData,
      });

      return response.json();
    } catch (error) {
      throw new Error(`Upload failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  /**
   * Download and decrypt a file from Bunkor
   *
   * @param fileId File ID from Bunkor
   * @param password Decryption password
   * @param onProgress Optional progress callback (0-100)
   * @returns Decrypted file blob
   *
   * @example
   * ```typescript
   * const decrypted = await client.downloadDecrypted(
   *   'file_abc123',
   *   'secure-password',
   *   (progress) => console.log(`Downloaded: ${progress}%`)
   * );
   *
   * // Download to user's device
   * const url = URL.createObjectURL(decrypted);
   * const a = document.createElement('a');
   * a.href = url;
   * a.download = 'document.pdf';
   * a.click();
   * ```
   */
  async downloadDecrypted(
    fileId: string,
    password: string,
    onProgress?: (progress: number) => void
  ): Promise<Blob> {
    try {
      // Get file metadata first
      const metadata = await this.getFileMetadata(fileId);

      if (onProgress) onProgress(10);

      // Download encrypted file
      const downloadUrl = BUNKOR_ENDPOINTS.DOWNLOAD.replace(':fileId', fileId);
      const response = await this.fetchBunkor(downloadUrl);

      if (onProgress) onProgress(50);

      const encryptedBlob = await response.blob();

      if (onProgress) onProgress(70);

      // Decrypt file
      const decrypted = await this.encryptionService.decryptFile(
        {
          encryptedBlob,
          password,
          algorithm: metadata.encryptionAlgorithm,
          salt: metadata.salt,
          iv: metadata.iv,
        },
        (progress) => {
          if (onProgress) onProgress(70 + Math.round(progress * 0.3));
        }
      );

      if (onProgress) onProgress(100);

      return decrypted;
    } catch (error) {
      throw new Error(`Download failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  /**
   * Get file metadata from Bunkor (encryption details, size, etc.)
   */
  async getFileMetadata(fileId: string): Promise<BunkorFileMetadata> {
    const url = BUNKOR_ENDPOINTS.GET_FILE.replace(':fileId', fileId);
    const response = await this.fetchBunkor(url);
    return response.json();
  }

  /**
   * Delete a file from Bunkor
   */
  async deleteFile(fileId: string): Promise<void> {
    const url = BUNKOR_ENDPOINTS.DELETE_FILE.replace(':fileId', fileId);
    await this.fetchBunkor(url, { method: 'DELETE' });
  }

  /**
   * List all files in the organization
   */
  async listFiles(options?: { limit?: number; offset?: number }): Promise<BunkorFileMetadata[]> {
    const params = new URLSearchParams();
    if (options?.limit) params.append('limit', String(options.limit));
    if (options?.offset) params.append('offset', String(options.offset));

    const url = `${BUNKOR_ENDPOINTS.LIST_FILES}${params.toString() ? '?' + params.toString() : ''}`;
    const response = await this.fetchBunkor(url);
    const data = await response.json();
    return data.files || [];
  }

  /**
   * Share a file with another user
   */
  async shareFile(
    fileId: string,
    email: string,
    expiresIn?: number
  ): Promise<{ shareId: string; shareUrl: string }> {
    const url = BUNKOR_ENDPOINTS.SHARE.replace(':fileId', fileId);
    const response = await this.fetchBunkor(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, expiresIn }),
    });
    return response.json();
  }

  /**
   * Get audit log for a file
   */
  async getAuditLog(fileId: string): Promise<Array<{
    timestamp: string;
    action: string;
    user: string;
    ipAddress: string;
  }>> {
    const url = BUNKOR_ENDPOINTS.AUDIT_LOG.replace(':fileId', fileId);
    const response = await this.fetchBunkor(url);
    const data = await response.json();
    return data.auditLog || [];
  }

  /**
   * Check Bunkor API health/connectivity
   */
  async healthCheck(): Promise<boolean> {
    try {
      const response = await this.fetchBunkor(BUNKOR_ENDPOINTS.HEALTH);
      return response.ok;
    } catch {
      return false;
    }
  }

  /**
   * Internal: Generate IV for encryption algorithm
   */
  private generateIv(algorithm: EncryptionAlgorithm): string {
    const ivSize = {
      'AES-256-GCM': 12,
      'AES-256-CBC': 16,
      'AES-256-CTR': 16,
      'Kyber-768-AES': 12,
      'Kyber-1024-AES': 12,
    }[algorithm];

    const array = new Uint8Array(ivSize);
    crypto.getRandomValues(array);
    return Array.from(array).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  /**
   * Internal: Calculate SHA-256 checksum of file
   */
  private async calculateChecksum(blob: Blob): Promise<string> {
    const buffer = await blob.arrayBuffer();
    const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  }

  /**
   * Internal: Make authenticated request to Bunkor API
   */
  private async fetchBunkor(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<Response> {
    const url = `${this.config.apiUrl}${endpoint}`;

    const headers = new Headers(options.headers);
    if (this.config.apiToken) {
      headers.set('Authorization', `Bearer ${this.config.apiToken}`);
    }
    if (this.config.organizationId) {
      headers.set('X-Organization-ID', this.config.organizationId);
    }

    if (this.config.debug) {
      console.log(`[Bunkor] ${options.method || 'GET'} ${endpoint}`);
    }

    const response = await fetch(url, {
      ...options,
      headers,
      timeout: this.config.timeout,
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Bunkor API error (${response.status}): ${error}`);
    }

    return response;
  }
}
