import { IEncryptionStrategy, EncryptionResult, DecryptionParams } from '../encryption-strategy.interface';

/**
 * RSA-OAEP Encryption Strategy
 *
 * Asymmetric encryption for small data
 * - Public key encryption
 * - Suitable for encrypting symmetric keys
 * - NOT suitable for large files (use hybrid encryption instead)
 * - Built into Web Crypto API
 *
 * NOTE: For file encryption, this should be used in hybrid mode:
 * 1. Generate random AES key
 * 2. Encrypt file with AES key
 * 3. Encrypt AES key with RSA public key
 */
export class RsaOaepStrategy implements IEncryptionStrategy {
  readonly algorithmName = 'RSA-OAEP';
  readonly isSupported = true;
  readonly requiresExternalLibrary = false;

  // RSA is not suitable for direct file encryption
  // This is a placeholder for hybrid encryption support
  private readonly MAX_ENCRYPT_SIZE = 190; // bytes for 2048-bit key

  getIvSize(): number {
    return 0; // RSA doesn't use IV
  }

  getSaltSize(): number {
    return 0; // RSA doesn't use salt in the same way
  }

  async encrypt(
    data: ArrayBuffer,
    password: string,
    salt: string,
    iv: string
  ): Promise<EncryptionResult> {
    // For now, throw an error indicating this needs hybrid implementation
    throw new Error(
      'RSA-OAEP requires hybrid encryption for file encryption. ' +
      'Use AES-256-GCM for file encryption instead, or implement hybrid mode.'
    );
  }

  async decrypt(params: DecryptionParams): Promise<Blob> {
    throw new Error(
      'RSA-OAEP requires hybrid decryption for file decryption. ' +
      'This feature is not yet implemented.'
    );
  }
}
