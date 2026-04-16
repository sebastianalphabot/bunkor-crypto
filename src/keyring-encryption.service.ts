/**
 * Keyring Encryption Service
 *
 * Single Responsibility: Encrypt/decrypt the password keyring using a master password
 * Uses Web Crypto API for secure encryption
 *
 * Algorithm: AES-256-GCM with PBKDF2 key derivation
 * - PBKDF2 iterations: 310,000 (OWASP 2023 recommendation)
 * - Salt: 32 bytes (256 bits)
 * - IV: 12 bytes (96 bits) for GCM
 */
export class KeyringEncryptionService {
  private readonly PBKDF2_ITERATIONS = 310000;
  private readonly SALT_LENGTH = 32;
  private readonly IV_LENGTH = 12;

  /**
   * Encrypt data with master password
   * Returns encrypted data with salt and IV prepended
   */
  async encrypt(plaintext: string, masterPassword: string): Promise<string> {
    try {
      // Generate salt and IV
      const salt = crypto.getRandomValues(new Uint8Array(this.SALT_LENGTH));
      const iv = crypto.getRandomValues(new Uint8Array(this.IV_LENGTH));

      // Derive key from master password
      const key = await this.deriveKey(masterPassword, salt);

      // Encrypt the data
      const encoder = new TextEncoder();
      const data = encoder.encode(plaintext);

      const encryptedBuffer = await crypto.subtle.encrypt(
        {
          name: 'AES-GCM',
          iv: iv
        },
        key,
        data
      );

      // Combine salt + iv + encrypted data
      const encryptedArray = new Uint8Array(encryptedBuffer);
      const combined = new Uint8Array(
        this.SALT_LENGTH + this.IV_LENGTH + encryptedArray.length
      );

      combined.set(salt, 0);
      combined.set(iv, this.SALT_LENGTH);
      combined.set(encryptedArray, this.SALT_LENGTH + this.IV_LENGTH);

      // Return as base64
      return this.arrayBufferToBase64(combined);
    } catch (error) {
      console.error('Encryption failed:', error);
      throw new Error('Failed to encrypt keyring');
    }
  }

  /**
   * Decrypt data with master password
   */
  async decrypt(encryptedData: string, masterPassword: string): Promise<string> {
    try {
      // Decode base64
      const combined = this.base64ToArrayBuffer(encryptedData);

      // Extract salt, IV, and encrypted data
      const salt = combined.slice(0, this.SALT_LENGTH);
      const iv = combined.slice(this.SALT_LENGTH, this.SALT_LENGTH + this.IV_LENGTH);
      const encryptedArray = combined.slice(this.SALT_LENGTH + this.IV_LENGTH);

      // Derive key from master password
      const key = await this.deriveKey(masterPassword, salt);

      // Decrypt the data
      const decryptedBuffer = await crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: iv
        },
        key,
        encryptedArray
      );

      // Convert back to string
      const decoder = new TextDecoder();
      return decoder.decode(decryptedBuffer);
    } catch (error) {
      console.error('Decryption failed:', error);
      throw new Error('Failed to decrypt keyring - incorrect master password');
    }
  }

  /**
   * Verify if master password is correct by attempting to decrypt
   */
  async verifyMasterPassword(
    encryptedData: string,
    masterPassword: string
  ): Promise<boolean> {
    try {
      await this.decrypt(encryptedData, masterPassword);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Derive encryption key from master password using PBKDF2
   */
  private async deriveKey(
    password: string,
    salt: Uint8Array
  ): Promise<CryptoKey> {
    const encoder = new TextEncoder();
    const passwordBuffer = encoder.encode(password);

    // Import password as key material
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      passwordBuffer,
      'PBKDF2',
      false,
      ['deriveKey']
    );

    // Derive AES key
    return await crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: salt.buffer as ArrayBuffer,
        iterations: this.PBKDF2_ITERATIONS,
        hash: 'SHA-256'
      },
      keyMaterial,
      {
        name: 'AES-GCM',
        length: 256
      },
      false,
      ['encrypt', 'decrypt']
    );
  }

  /**
   * Convert ArrayBuffer to Base64
   */
  private arrayBufferToBase64(buffer: Uint8Array): string {
    let binary = '';
    const len = buffer.byteLength;
    for (let i = 0; i < len; i++) {
      binary += String.fromCharCode(buffer[i]);
    }
    return btoa(binary);
  }

  /**
   * Convert Base64 to ArrayBuffer
   */
  private base64ToArrayBuffer(base64: string): Uint8Array {
    const binary = atob(base64);
    const len = binary.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }
}
