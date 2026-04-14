/**
 * @bunkor/crypto - Utility Functions
 *
 * Common cryptographic operations and helpers
 */

/**
 * Generate a cryptographically secure random string
 * @param length Length in bytes
 * @returns Base64-encoded random string
 */
export function generateRandomString(length: number = 32): string {
  const array = new Uint8Array(length);
  crypto.getRandomValues(array);
  return arrayBufferToBase64(array);
}

/**
 * Generate a cryptographically secure random hex string
 * @param length Length in bytes
 * @returns Hex-encoded random string
 */
export function generateRandomHex(length: number = 32): string {
  const array = new Uint8Array(length);
  crypto.getRandomValues(array);
  return arrayBufferToHex(array);
}

/**
 * Convert Uint8Array to base64
 */
export function arrayBufferToBase64(buffer: Uint8Array | ArrayBuffer): string {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

/**
 * Convert base64 string to Uint8Array
 */
export function base64ToArrayBuffer(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Convert Uint8Array to hex string
 */
export function arrayBufferToHex(buffer: Uint8Array | ArrayBuffer): string {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Convert hex string to Uint8Array
 */
export function hexToArrayBuffer(hex: string): Uint8Array {
  if (!/^[0-9a-fA-F]*$/.test(hex)) {
    throw new Error('Invalid hex string: contains non-hex characters');
  }
  if (hex.length % 2 !== 0) {
    throw new Error('Invalid hex string: length must be even');
  }

  const length = hex.length / 2;
  const array = new Uint8Array(length);

  for (let i = 0; i < length; i++) {
    array[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }

  return array;
}

/**
 * Calculate SHA-256 hash of data
 * @param data Data to hash
 * @returns Hex-encoded hash
 */
export async function sha256(data: string | ArrayBuffer | Uint8Array): Promise<string> {
  let buffer: string | ArrayBuffer | Uint8Array;

  if (typeof data === 'string') {
    buffer = new TextEncoder().encode(data);
  } else {
    buffer = data;
  }

  const hashBuffer = await crypto.subtle.digest('SHA-256', buffer as BufferSource);
  return arrayBufferToHex(hashBuffer);
}

/**
 * Validate password strength
 * @returns Object with validity and message if invalid
 */
export function validatePassword(password: string): { valid: boolean; message?: string } {
  if (!password) {
    return { valid: false, message: 'Password is required' };
  }

  if (password.length < 8) {
    return { valid: false, message: 'Password must be at least 8 characters' };
  }

  const hasUppercase = /[A-Z]/.test(password);
  const hasLowercase = /[a-z]/.test(password);
  const hasNumber = /[0-9]/.test(password);
  const hasSpecial = /[^A-Za-z0-9]/.test(password);

  if (!hasUppercase || !hasLowercase || !hasNumber || !hasSpecial) {
    return {
      valid: false,
      message: 'Password must include uppercase, lowercase, number, and special character',
    };
  }

  return { valid: true };
}

/**
 * Calculate password strength (0-100)
 */
export function calculatePasswordStrength(password: string): number {
  let strength = 0;

  if (password.length >= 8) strength += 20;
  if (password.length >= 12) strength += 20;
  if (password.length >= 16) strength += 10;
  if (/[a-z]/.test(password)) strength += 10;
  if (/[A-Z]/.test(password)) strength += 10;
  if (/[0-9]/.test(password)) strength += 15;
  if (/[^A-Za-z0-9]/.test(password)) strength += 15;

  return Math.min(strength, 100);
}

/**
 * Format bytes for display
 */
export function formatBytes(bytes: number, decimals: number = 2): string {
  if (bytes === 0) return '0 Bytes';

  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));

  return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

/**
 * Generate a deterministic key from a seed (for testing/reproducibility)
 * WARNING: Do not use for production security-critical operations
 */
export async function deriveKeyFromSeed(
  seed: string,
  keyLength: number = 32
): Promise<Uint8Array> {
  const encoder = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(seed),
    'PBKDF2',
    false,
    ['deriveBits']
  );

  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: encoder.encode(''),
      iterations: 1000, // Low iterations for test/demo only
      hash: 'SHA-256',
    },
    keyMaterial,
    keyLength * 8
  );

  return new Uint8Array(derivedBits);
}

/**
 * Secure string comparison (timing-safe)
 * Prevents timing attacks when comparing sensitive strings
 */
export function secureCompare(a: string, b: string): boolean {
  if (a.length !== b.length) return false;

  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }

  return result === 0;
}

/**
 * Safely clear sensitive data from memory
 * Note: JavaScript doesn't guarantee memory clearing, but this helps
 */
export function clearSensitiveData(data: Uint8Array | ArrayBuffer): void {
  if (data instanceof Uint8Array) {
    data.fill(0);
  } else {
    new Uint8Array(data).fill(0);
  }
}

/**
 * Check if Web Crypto API is available
 */
export function isWebCryptoAvailable(): boolean {
  return typeof crypto !== 'undefined' && typeof crypto.subtle !== 'undefined';
}

/**
 * Check browser encryption support
 */
export function checkEncryptionSupport(): {
  webCrypto: boolean;
  aesGcm: boolean;
  aesCbc: boolean;
  aesStr: boolean;
  rsaOaep: boolean;
  pbkdf2: boolean;
} {
  const webCrypto = isWebCryptoAvailable();

  return {
    webCrypto,
    aesGcm: webCrypto, // Modern browsers all support AES-GCM
    aesCbc: webCrypto,
    aesStr: webCrypto,
    rsaOaep: webCrypto,
    pbkdf2: webCrypto,
  };
}

/**
 * Get browser encryption capabilities summary
 */
export function getEncryptionCapabilities(): string {
  const support = checkEncryptionSupport();

  if (!support.webCrypto) {
    return 'Your browser does not support Web Crypto API. Please upgrade.';
  }

  const supported = Object.entries(support)
    .filter(([, v]) => v)
    .map(([k]) => k)
    .join(', ');

  return `Supported: ${supported}`;
}
