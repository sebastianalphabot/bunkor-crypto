import { WebCryptoStrategy, EncryptionResult, DecryptionParams } from '../encryption-strategy.interface';

/**
 * AES-256-GCM Encryption Strategy
 *
 * Authenticated Encryption with Associated Data (AEAD)
 * - Provides both confidentiality and authenticity
 * - Recommended for most use cases
 * - Built into Web Crypto API
 */
export class AesGcmStrategy extends WebCryptoStrategy {
  readonly algorithmName = 'AES-256-GCM';

  getIvSize(): number {
    return 12; // 96 bits recommended for GCM
  }

  async encrypt(
    data: ArrayBuffer,
    password: string,
    salt: string,
    ivHex: string
  ): Promise<EncryptionResult> {
    const key = await this.deriveKey(password, salt, 'AES-GCM');
    const iv = this.hexToUint8Array(ivHex);

    const encryptedBuffer = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: iv.buffer as ArrayBuffer },
      key,
      data
    );

    return {
      encryptedBlob: new Blob([encryptedBuffer]),
      iv: ivHex,
      salt
    };
  }

  async decrypt(params: DecryptionParams): Promise<Blob> {
    const key = await this.deriveKey(params.password, params.salt, 'AES-GCM');
    const iv = this.hexToUint8Array(params.iv);
    const encryptedData = await params.encryptedBlob.arrayBuffer();

    try {
      const decryptedBuffer = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: iv.buffer as ArrayBuffer },
        key,
        encryptedData
      );

      return new Blob([decryptedBuffer]);
    } catch (error) {
      throw new Error('Decryption failed. Please check your password.');
    }
  }
}
