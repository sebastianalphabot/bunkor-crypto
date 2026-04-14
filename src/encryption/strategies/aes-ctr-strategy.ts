import { WebCryptoStrategy, EncryptionResult, DecryptionParams } from '../encryption-strategy.interface';

/**
 * AES-256-CTR Encryption Strategy
 *
 * Counter mode - converts block cipher into stream cipher
 * - No padding required
 * - Parallelizable encryption/decryption
 * - Built into Web Crypto API
 */
export class AesCtrStrategy extends WebCryptoStrategy {
  readonly algorithmName = 'AES-256-CTR';

  getIvSize(): number {
    return 16; // 128 bits for CTR
  }

  async encrypt(
    data: ArrayBuffer,
    password: string,
    salt: string,
    ivHex: string
  ): Promise<EncryptionResult> {
    const key = await this.deriveKey(password, salt, 'AES-CTR');
    const iv = this.hexToUint8Array(ivHex);

    const encryptedBuffer = await crypto.subtle.encrypt(
      {
        name: 'AES-CTR',
        counter: iv.buffer as ArrayBuffer,
        length: 64 // Counter length in bits
      },
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
    const key = await this.deriveKey(params.password, params.salt, 'AES-CTR');
    const iv = this.hexToUint8Array(params.iv);
    const encryptedData = await params.encryptedBlob.arrayBuffer();

    try {
      const decryptedBuffer = await crypto.subtle.decrypt(
        {
          name: 'AES-CTR',
          counter: iv.buffer as ArrayBuffer,
          length: 64
        },
        key,
        encryptedData
      );

      return new Blob([decryptedBuffer]);
    } catch (error) {
      throw new Error('Decryption failed. Please check your password.');
    }
  }
}
