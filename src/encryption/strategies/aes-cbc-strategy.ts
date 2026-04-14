import { WebCryptoStrategy, EncryptionResult, DecryptionParams } from '../encryption-strategy.interface';

/**
 * AES-256-CBC Encryption Strategy
 *
 * Classic block cipher mode
 * - Widely supported and well-tested
 * - Requires padding
 * - Built into Web Crypto API
 */
export class AesCbcStrategy extends WebCryptoStrategy {
  readonly algorithmName = 'AES-256-CBC';

  getIvSize(): number {
    return 16; // 128 bits for CBC
  }

  async encrypt(
    data: ArrayBuffer,
    password: string,
    salt: string,
    ivHex: string
  ): Promise<EncryptionResult> {
    const key = await this.deriveKey(password, salt, 'AES-CBC');
    const iv = this.hexToUint8Array(ivHex);

    const encryptedBuffer = await crypto.subtle.encrypt(
      { name: 'AES-CBC', iv: iv.buffer as ArrayBuffer },
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
    const key = await this.deriveKey(params.password, params.salt, 'AES-CBC');
    const iv = this.hexToUint8Array(params.iv);
    const encryptedData = await params.encryptedBlob.arrayBuffer();

    try {
      const decryptedBuffer = await crypto.subtle.decrypt(
        { name: 'AES-CBC', iv: iv.buffer as ArrayBuffer },
        key,
        encryptedData
      );

      return new Blob([decryptedBuffer]);
    } catch (error) {
      throw new Error('Decryption failed. Please check your password.');
    }
  }
}
