/**
 * Encryption Strategy Interface (Strategy Pattern - GoF Design Pattern)
 *
 * SOLID Principles:
 * - Interface Segregation: Focused interface for encryption strategies
 * - Open/Closed: Open for extension, closed for modification
 * - Liskov Substitution: Any strategy can substitute another
 */

export interface EncryptionResult {
  encryptedBlob: Blob;
  iv: string;
  salt: string;
}

export interface DecryptionParams {
  encryptedBlob: Blob;
  password: string;
  iv: string;
  salt: string;
}

/**
 * Base Encryption Strategy Interface
 * Each encryption algorithm implements this interface
 */
export interface IEncryptionStrategy {
  readonly algorithmName: string;
  readonly isSupported: boolean;
  readonly requiresExternalLibrary: boolean;

  /**
   * Encrypt data using this strategy
   */
  encrypt(
    data: ArrayBuffer,
    password: string,
    salt: string,
    iv: string
  ): Promise<EncryptionResult>;

  /**
   * Decrypt data using this strategy
   */
  decrypt(params: DecryptionParams): Promise<Blob>;

  /**
   * Get recommended IV size for this algorithm
   */
  getIvSize(): number;

  /**
   * Get recommended salt size for this algorithm
   */
  getSaltSize(): number;
}

/**
 * Base class for Web Crypto API-based strategies
 * Template Method Pattern for common functionality
 */
export abstract class WebCryptoStrategy implements IEncryptionStrategy {
  abstract readonly algorithmName: string;
  readonly isSupported = true;
  readonly requiresExternalLibrary = false;

  protected readonly PBKDF2_ITERATIONS = 100000;
  protected readonly KEY_LENGTH = 256;

  abstract encrypt(
    data: ArrayBuffer,
    password: string,
    salt: string,
    iv: string
  ): Promise<EncryptionResult>;

  abstract decrypt(params: DecryptionParams): Promise<Blob>;

  abstract getIvSize(): number;

  getSaltSize(): number {
    return 32; // 256 bits for all algorithms
  }

  /**
   * Derive encryption key from password using PBKDF2
   * Template Method Pattern: Common key derivation logic
   */
  protected async deriveKey(
    password: string,
    saltHex: string,
    algorithm: 'AES-GCM' | 'AES-CBC' | 'AES-CTR'
  ): Promise<CryptoKey> {
    const passwordBuffer = new TextEncoder().encode(password);
    const saltBuffer = this.hexToUint8Array(saltHex);

    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      passwordBuffer,
      'PBKDF2',
      false,
      ['deriveBits', 'deriveKey']
    );

    return await crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: saltBuffer.buffer as ArrayBuffer,
        iterations: this.PBKDF2_ITERATIONS,
        hash: 'SHA-256'
      },
      keyMaterial,
      { name: algorithm, length: this.KEY_LENGTH },
      false,
      ['encrypt', 'decrypt']
    );
  }

  /**
   * Utility: Convert hex string to Uint8Array
   * IMPORTANT: Creates a new ArrayBuffer to ensure Chrome compatibility.
   * Chrome's Web Crypto API requires the ArrayBuffer to exactly match the
   * Uint8Array's content, not reference a larger underlying buffer.
   */
  protected hexToUint8Array(hex: string): Uint8Array {
    const matches = hex.match(/.{1,2}/g);
    if (!matches) {
      throw new Error('Invalid hex string');
    }
    const bytes = matches.map(byte => parseInt(byte, 16));
    // Create a fresh ArrayBuffer with exact size for Chrome compatibility
    const buffer = new ArrayBuffer(bytes.length);
    const uint8Array = new Uint8Array(buffer);
    uint8Array.set(bytes);
    return uint8Array;
  }

  /**
   * Utility: Convert ArrayBuffer to hex string
   */
  protected arrayBufferToHex(buffer: ArrayBuffer | Uint8Array): string {
    const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    return Array.from(bytes)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }
}
