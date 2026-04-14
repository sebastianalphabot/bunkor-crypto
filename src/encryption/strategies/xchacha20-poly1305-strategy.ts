import { IEncryptionStrategy, EncryptionResult, DecryptionParams } from '../encryption-strategy.interface';
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { pbkdf2 } from '@noble/hashes/pbkdf2.js';
import { sha256 } from '@noble/hashes/sha2.js';

/**
 * XChaCha20-Poly1305 Encryption Strategy
 *
 * SOLID Principles:
 * - Single Responsibility: Handles XChaCha20-Poly1305 encryption/decryption
 * - Open/Closed: Implements IEncryptionStrategy interface
 * - Liskov Substitution: Can substitute any IEncryptionStrategy
 * - Interface Segregation: Focused interface
 * - Dependency Inversion: Depends on IEncryptionStrategy abstraction
 *
 * Algorithm Details:
 * - XChaCha20-Poly1305 is an extended nonce variant of ChaCha20-Poly1305
 * - XChaCha20: Extended nonce stream cipher (192-bit nonce)
 * - Poly1305: Message authentication code
 * - Advantages over ChaCha20-Poly1305:
 *   * 192-bit nonce (vs 96-bit) allows random nonce generation without collision risk
 *   * Better for scenarios where nonce management is difficult
 *   * Used in modern protocols like WireGuard
 * - 256-bit key, 192-bit nonce (IV)
 */
export class XChaCha20Poly1305Strategy implements IEncryptionStrategy {
  readonly algorithmName = 'XChaCha20-Poly1305';
  readonly isSupported = true;
  readonly requiresExternalLibrary = true; // Uses @noble/ciphers

  private readonly PBKDF2_ITERATIONS = 100000;
  private readonly KEY_LENGTH = 32; // 256 bits
  private readonly IV_SIZE = 24; // 192 bits (extended nonce for XChaCha20)
  private readonly SALT_SIZE = 32; // 256 bits

  /**
   * Get recommended IV (nonce) size
   */
  getIvSize(): number {
    return this.IV_SIZE;
  }

  /**
   * Get recommended salt size
   */
  getSaltSize(): number {
    return this.SALT_SIZE;
  }

  /**
   * Encrypt data using XChaCha20-Poly1305
   */
  async encrypt(
    data: ArrayBuffer,
    password: string,
    saltHex: string,
    ivHex: string
  ): Promise<EncryptionResult> {
    // Derive key from password using PBKDF2
    const key = await this.deriveKey(password, saltHex);

    // Convert IV from hex to Uint8Array
    const nonce = this.hexToUint8Array(ivHex);

    // Validate nonce size
    if (nonce.length !== this.IV_SIZE) {
      throw new Error(`Invalid nonce size: expected ${this.IV_SIZE} bytes, got ${nonce.length}`);
    }

    // Convert data to Uint8Array
    const plaintext = new Uint8Array(data);

    // Encrypt using XChaCha20-Poly1305
    // The Noble library automatically appends the 16-byte Poly1305 tag
    const cipher = xchacha20poly1305(key, nonce);
    const ciphertext = cipher.encrypt(plaintext);

    // Create a new Uint8Array to ensure proper buffer type
    const result = new Uint8Array(ciphertext);

    return {
      encryptedBlob: new Blob([result]),
      iv: ivHex,
      salt: saltHex
    };
  }

  /**
   * Decrypt data using XChaCha20-Poly1305
   */
  async decrypt(params: DecryptionParams): Promise<Blob> {
    // Derive key from password using PBKDF2
    const key = await this.deriveKey(params.password, params.salt);

    // Convert IV from hex to Uint8Array
    const nonce = this.hexToUint8Array(params.iv);

    // Validate nonce size
    if (nonce.length !== this.IV_SIZE) {
      throw new Error(`Invalid nonce size: expected ${this.IV_SIZE} bytes, got ${nonce.length}`);
    }

    // Convert encrypted data to Uint8Array
    const ciphertext = new Uint8Array(await params.encryptedBlob.arrayBuffer());

    try {
      // Decrypt using XChaCha20-Poly1305
      // The Noble library automatically verifies and removes the Poly1305 tag
      const cipher = xchacha20poly1305(key, nonce);
      const plaintext = cipher.decrypt(ciphertext);

      // Create a new Uint8Array to ensure proper buffer type
      const result = new Uint8Array(plaintext);

      return new Blob([result]);
    } catch (error) {
      throw new Error('Decryption failed. Please check your password.');
    }
  }

  /**
   * Derive encryption key from password using PBKDF2
   *
   * PBKDF2 (Password-Based Key Derivation Function 2):
   * - Derives a cryptographic key from a password
   * - Uses salt to prevent rainbow table attacks
   * - Uses iterations to slow down brute-force attacks
   * - NIST approved (FIPS 140-2)
   */
  private async deriveKey(password: string, saltHex: string): Promise<Uint8Array> {
    const passwordBytes = new TextEncoder().encode(password);
    const saltBytes = this.hexToUint8Array(saltHex);

    // Derive 256-bit key using PBKDF2-SHA256
    const key = pbkdf2(sha256, passwordBytes, saltBytes, {
      c: this.PBKDF2_ITERATIONS,
      dkLen: this.KEY_LENGTH
    });

    return key;
  }

  /**
   * Convert hex string to Uint8Array
   */
  private hexToUint8Array(hex: string): Uint8Array {
    const matches = hex.match(/.{1,2}/g);
    if (!matches) {
      throw new Error('Invalid hex string');
    }
    return new Uint8Array(matches.map(byte => parseInt(byte, 16)));
  }
}
