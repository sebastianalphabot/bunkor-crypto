import { Injectable } from '@angular/core';

/**
 * Cryptographic utilities for zero-knowledge password handling
 * Used for PBKDF2 hashing before sending to backend
 */
@Injectable({
  providedIn: 'root'
})
export class CryptoService {

  /**
   * Generate a cryptographically secure random salt
   * @param length Salt length in bytes (default: 32)
   * @returns Base64-encoded salt
   */
  generateSalt(length: number = 32): string {
    const array = new Uint8Array(length);
    crypto.getRandomValues(array);
    return this.arrayBufferToBase64(array);
  }

  /**
   * Hash password using PBKDF2
   * @param password Raw password string
   * @param salt Base64-encoded salt (if not provided, generates new one)
   * @param iterations PBKDF2 iterations (default: 600000)
   * @returns Promise<{ hash: string, salt: string }>
   */
  async hashPassword(
    password: string,
    salt?: string,
    iterations: number = 600000
  ): Promise<{ hash: string; salt: string }> {
    // Generate salt if not provided
    const saltToUse = salt || this.generateSalt();
    const saltBuffer = this.base64ToArrayBuffer(saltToUse);

    // Convert password to buffer
    const encoder = new TextEncoder();
    const passwordBuffer = encoder.encode(password);

    // Import password as key material
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      passwordBuffer,
      'PBKDF2',
      false,
      ['deriveBits']
    );

    // Derive bits using PBKDF2
    const hashBuffer = await crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt: saltBuffer,
        iterations: iterations,
        hash: 'SHA-256'
      },
      keyMaterial,
      256 // 256 bits = 32 bytes
    );

    // Convert to base64
    const hash = this.arrayBufferToBase64(new Uint8Array(hashBuffer));

    return {
      hash,
      salt: saltToUse
    };
  }

  /**
   * Verify password against stored hash and salt
   * @param password Password to verify
   * @param storedHash Stored password hash
   * @param storedSalt Stored salt
   * @returns Promise<boolean> True if password matches
   */
  async verifyPassword(
    password: string,
    storedHash: string,
    storedSalt: string
  ): Promise<boolean> {
    const result = await this.hashPassword(password, storedSalt);
    return result.hash === storedHash;
  }

  /**
   * Convert ArrayBuffer to Base64 string
   */
  private arrayBufferToBase64(buffer: Uint8Array): string {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  /**
   * Convert Base64 string to ArrayBuffer
   */
  private base64ToArrayBuffer(base64: string): ArrayBuffer {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }
}
