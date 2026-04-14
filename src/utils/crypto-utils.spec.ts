import {
  generateRandomString,
  generateRandomHex,
  arrayBufferToBase64,
  base64ToArrayBuffer,
  arrayBufferToHex,
  hexToArrayBuffer,
  sha256,
  validatePassword,
  calculatePasswordStrength,
  formatBytes,
  secureCompare,
  isWebCryptoAvailable,
} from './crypto-utils';

describe('Crypto Utilities', () => {
  describe('Random Generation', () => {
    it('should generate random string', () => {
      const str = generateRandomString(32);
      expect(str).toBeTruthy();
      expect(typeof str).toBe('string');
      expect(str.length).toBeGreaterThan(0);
    });

    it('should generate different random strings', () => {
      const str1 = generateRandomString(32);
      const str2 = generateRandomString(32);
      expect(str1).not.toBe(str2);
    });

    it('should generate random hex', () => {
      const hex = generateRandomHex(16);
      expect(hex).toBeTruthy();
      expect(/^[0-9a-f]+$/.test(hex)).toBe(true);
    });

    it('should generate different random hex values', () => {
      const hex1 = generateRandomHex(16);
      const hex2 = generateRandomHex(16);
      expect(hex1).not.toBe(hex2);
    });
  });

  describe('Base64 Encoding/Decoding', () => {
    it('should encode and decode base64', () => {
      const original = new Uint8Array([1, 2, 3, 4, 5]);
      const encoded = arrayBufferToBase64(original);
      const decoded = base64ToArrayBuffer(encoded);

      expect(decoded).toEqual(original);
    });

    it('should handle empty buffer', () => {
      const empty = new Uint8Array([]);
      const encoded = arrayBufferToBase64(empty);
      const decoded = base64ToArrayBuffer(encoded);

      expect(decoded.length).toBe(0);
    });
  });

  describe('Hex Encoding/Decoding', () => {
    it('should encode and decode hex', () => {
      const original = new Uint8Array([255, 128, 64, 32, 16]);
      const encoded = arrayBufferToHex(original);
      const decoded = hexToArrayBuffer(encoded);

      expect(decoded).toEqual(original);
    });

    it('should produce lowercase hex', () => {
      const buffer = new Uint8Array([255, 170, 85]);
      const hex = arrayBufferToHex(buffer);

      expect(hex).toBe('ffaa55');
    });

    it('should reject invalid hex', () => {
      expect(() => hexToArrayBuffer('gggg')).toThrow();
      expect(() => hexToArrayBuffer('1')).toThrow();
    });
  });

  describe('Hashing', () => {
    it('should hash string to SHA-256', async () => {
      const hash = await sha256('test');
      expect(hash).toBeTruthy();
      expect(hash.length).toBe(64); // SHA-256 is 64 hex chars
      expect(/^[0-9a-f]+$/.test(hash)).toBe(true);
    });

    it('should produce same hash for same input', async () => {
      const hash1 = await sha256('test');
      const hash2 = await sha256('test');

      expect(hash1).toBe(hash2);
    });

    it('should produce different hash for different input', async () => {
      const hash1 = await sha256('test1');
      const hash2 = await sha256('test2');

      expect(hash1).not.toBe(hash2);
    });

    it('should hash ArrayBuffer', async () => {
      const buffer = new TextEncoder().encode('test');
      const hash = await sha256(buffer);

      expect(hash).toBeTruthy();
      expect(hash.length).toBe(64);
    });
  });

  describe('Password Validation', () => {
    it('should validate strong password', () => {
      const result = validatePassword('StrongPass123!');
      expect(result.valid).toBe(true);
      expect(result.message).toBeUndefined();
    });

    it('should reject password without uppercase', () => {
      const result = validatePassword('strongpass123!');
      expect(result.valid).toBe(false);
      expect(result.message).toBeTruthy();
    });

    it('should reject password without lowercase', () => {
      const result = validatePassword('STRONGPASS123!');
      expect(result.valid).toBe(false);
      expect(result.message).toBeTruthy();
    });

    it('should reject password without number', () => {
      const result = validatePassword('StrongPass!');
      expect(result.valid).toBe(false);
      expect(result.message).toBeTruthy();
    });

    it('should reject password without special character', () => {
      const result = validatePassword('StrongPass123');
      expect(result.valid).toBe(false);
      expect(result.message).toBeTruthy();
    });

    it('should reject short password', () => {
      const result = validatePassword('Pass1!');
      expect(result.valid).toBe(false);
      expect(result.message).toBeTruthy();
    });

    it('should reject empty password', () => {
      const result = validatePassword('');
      expect(result.valid).toBe(false);
      expect(result.message).toBeTruthy();
    });
  });

  describe('Password Strength', () => {
    it('should calculate strength for weak password', () => {
      const strength = calculatePasswordStrength('Weak1!');
      expect(strength).toBeLessThanOrEqual(50);
    });

    it('should calculate strength for medium password', () => {
      const strength = calculatePasswordStrength('Medium123!');
      expect(strength).toBeGreaterThanOrEqual(50);
      expect(strength).toBeLessThan(100);
    });

    it('should calculate strength for strong password', () => {
      const strength = calculatePasswordStrength('VeryStrongPass123456!');
      expect(strength).toBeGreaterThan(70);
    });

    it('should max out at 100', () => {
      const strength = calculatePasswordStrength('ThisIsAnExtremelyLongAndComplexPassword123!@#$%');
      expect(strength).toBeLessThanOrEqual(100);
    });
  });

  describe('Utilities', () => {
    it('should format bytes', () => {
      expect(formatBytes(0)).toBe('0 Bytes');
      expect(formatBytes(1024)).toContain('KB');
      expect(formatBytes(1024 * 1024)).toContain('MB');
      expect(formatBytes(1024 * 1024 * 1024)).toContain('GB');
    });

    it('should secure compare equal strings', () => {
      const result = secureCompare('test', 'test');
      expect(result).toBe(true);
    });

    it('should secure compare different strings', () => {
      const result = secureCompare('test1', 'test2');
      expect(result).toBe(false);
    });

    it('should reject different length strings', () => {
      const result = secureCompare('test', 'testing');
      expect(result).toBe(false);
    });

    it('should check Web Crypto availability', () => {
      const available = isWebCryptoAvailable();
      expect(typeof available).toBe('boolean');
    });
  });
});
