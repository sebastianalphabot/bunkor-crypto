import { IEncryptionStrategy } from './encryption-strategy.interface';
import { AesGcmStrategy } from './strategies/aes-gcm-strategy';
import { AesCbcStrategy } from './strategies/aes-cbc-strategy';
import { AesCtrStrategy } from './strategies/aes-ctr-strategy';
import { RsaOaepStrategy } from './strategies/rsa-oaep-strategy';
import { ChaCha20Poly1305Strategy } from './strategies/chacha20-poly1305-strategy';
import { XChaCha20Poly1305Strategy } from './strategies/xchacha20-poly1305-strategy';
import { KyberKemStrategy } from './strategies/kyber-kem-strategy';
import { DilithiumSignatureStrategy } from './strategies/dilithium-signature-strategy';

export type EncryptionAlgorithm =
  | 'AES-256-GCM'
  | 'AES-256-CBC'
  | 'AES-256-CTR'
  | 'RSA-OAEP'
  | 'ChaCha20-Poly1305'
  | 'XChaCha20-Poly1305'
  | 'Kyber-KEM'
  | 'Dilithium-Signature'
  | 'none';

export interface EncryptionResult {
  encryptedBlob: Blob;
  iv: string;
  algorithm: EncryptionAlgorithm;
  salt: string;
}

export interface DecryptionParams {
  encryptedBlob: Blob;
  password: string;
  iv: string;
  algorithm: EncryptionAlgorithm;
  salt: string;
}

export interface AlgorithmInfo {
  name: EncryptionAlgorithm;
  displayName: string;
  description: string;
  isSupported: boolean;
  requiresExternalLibrary: boolean;
  category: 'symmetric' | 'asymmetric' | 'post-quantum' | 'none';
  recommended: boolean;
}

/**
 * Enhanced Encryption Service using Strategy Pattern
 *
 * SOLID Principles Applied:
 * - Single Responsibility: Manages encryption strategy selection and execution
 * - Open/Closed: Open for new strategies, closed for modification
 * - Liskov Substitution: All strategies are interchangeable
 * - Interface Segregation: IEncryptionStrategy is focused
 * - Dependency Inversion: Depends on IEncryptionStrategy abstraction
 *
 * Design Patterns:
 * - Strategy Pattern: Different encryption algorithms
 * - Factory Pattern: Creates appropriate strategy based on algorithm
 */
export class EnhancedEncryptionService {
  private readonly strategies = new Map<EncryptionAlgorithm, IEncryptionStrategy>();

  constructor() {
    this.initializeStrategies();
  }

  /**
   * Initialize all encryption strategies (Factory Pattern)
   */
  private initializeStrategies(): void {
    // Supported algorithms (Web Crypto API)
    this.strategies.set('AES-256-GCM', new AesGcmStrategy());
    this.strategies.set('AES-256-CBC', new AesCbcStrategy());
    this.strategies.set('AES-256-CTR', new AesCtrStrategy());
    this.strategies.set('RSA-OAEP', new RsaOaepStrategy());

    // Unsupported algorithms (require external libraries)
    this.strategies.set('ChaCha20-Poly1305', new ChaCha20Poly1305Strategy());
    this.strategies.set('XChaCha20-Poly1305', new XChaCha20Poly1305Strategy());
    this.strategies.set('Kyber-KEM', new KyberKemStrategy());
    this.strategies.set('Dilithium-Signature', new DilithiumSignatureStrategy());
  }

  /**
   * Get all available algorithms with their info
   */
  getAvailableAlgorithms(): AlgorithmInfo[] {
    return [
      {
        name: 'AES-256-GCM',
        displayName: 'AES-256-GCM (Recommended)',
        description: 'Authenticated encryption with built-in integrity verification',
        isSupported: true,
        requiresExternalLibrary: false,
        category: 'symmetric',
        recommended: true
      },
      {
        name: 'AES-256-CBC',
        displayName: 'AES-256-CBC',
        description: 'Classic block cipher mode, widely supported',
        isSupported: true,
        requiresExternalLibrary: false,
        category: 'symmetric',
        recommended: false
      },
      {
        name: 'AES-256-CTR',
        displayName: 'AES-256-CTR',
        description: 'Counter mode, no padding required',
        isSupported: true,
        requiresExternalLibrary: false,
        category: 'symmetric',
        recommended: false
      },
      {
        name: 'RSA-OAEP',
        displayName: 'RSA-OAEP (Hybrid Only)',
        description: 'Asymmetric encryption for key exchange',
        isSupported: false,
        requiresExternalLibrary: false,
        category: 'asymmetric',
        recommended: false
      },
      {
        name: 'ChaCha20-Poly1305',
        displayName: 'ChaCha20-Poly1305',
        description: 'Modern authenticated encryption, faster on mobile devices',
        isSupported: true,
        requiresExternalLibrary: true,
        category: 'symmetric',
        recommended: false
      },
      {
        name: 'XChaCha20-Poly1305',
        displayName: 'XChaCha20-Poly1305',
        description: 'Extended nonce ChaCha20, ideal for random nonces',
        isSupported: true,
        requiresExternalLibrary: true,
        category: 'symmetric',
        recommended: false
      },
      {
        name: 'Kyber-KEM',
        displayName: 'Kyber-KEM (Post-Quantum)',
        description: 'Post-quantum key encapsulation mechanism',
        isSupported: true,
        requiresExternalLibrary: true,
        category: 'post-quantum',
        recommended: false
      },
      {
        name: 'Dilithium-Signature',
        displayName: 'Dilithium (Post-Quantum)',
        description: 'Post-quantum digital signatures - temporarily unavailable (WASM compatibility issue)',
        isSupported: false,
        requiresExternalLibrary: true,
        category: 'post-quantum',
        recommended: false
      },
      {
        name: 'none',
        displayName: 'No Encryption',
        description: 'Upload without encryption',
        isSupported: true,
        requiresExternalLibrary: false,
        category: 'none',
        recommended: false
      }
    ];
  }

  /**
   * Get supported algorithms only
   */
  getSupportedAlgorithms(): AlgorithmInfo[] {
    return this.getAvailableAlgorithms().filter(alg => alg.isSupported);
  }

  /**
   * Encrypt file using selected algorithm (Strategy Pattern)
   */
  async encryptFile(params: {
    file: Blob;
    password: string;
    algorithm: EncryptionAlgorithm;
    salt: string;
    iv: string;
  }): Promise<EncryptionResult> {
    if (params.algorithm === 'none') {
      throw new Error('Use algorithm "none" for unencrypted uploads');
    }

    const strategy = this.strategies.get(params.algorithm);
    if (!strategy) {
      throw new Error(`Unknown encryption algorithm: ${params.algorithm}`);
    }

    if (!strategy.isSupported) {
      throw new Error(
        `${params.algorithm} is not yet supported. ${strategy.requiresExternalLibrary ? 'Requires external library.' : ''}`
      );
    }

    const fileBuffer = await params.file.arrayBuffer();
    const result = await strategy.encrypt(fileBuffer, params.password, params.salt, params.iv);

    return {
      ...result,
      algorithm: params.algorithm
    };
  }

  /**
   * Decrypt file using selected algorithm (Strategy Pattern)
   */
  async decryptFile(params: DecryptionParams): Promise<Blob> {
    if (params.algorithm === 'none') {
      return params.encryptedBlob;
    }

    const strategy = this.strategies.get(params.algorithm);
    if (!strategy) {
      throw new Error(`Unknown decryption algorithm: ${params.algorithm}`);
    }

    if (!strategy.isSupported) {
      throw new Error(`${params.algorithm} is not yet supported`);
    }

    return await strategy.decrypt(params);
  }

  /**
   * Validate password strength
   */
  validatePassword(password: string): { valid: boolean; message?: string } {
    if (password.length < 8) {
      return { valid: false, message: 'Password must be at least 8 characters' };
    }

    const hasUpper = /[A-Z]/.test(password);
    const hasLower = /[a-z]/.test(password);
    const hasNumber = /[0-9]/.test(password);
    const hasSymbol = /[^A-Za-z0-9]/.test(password);

    const strength = [hasUpper, hasLower, hasNumber, hasSymbol].filter(Boolean).length;

    if (strength < 3) {
      return {
        valid: false,
        message: 'Password must contain uppercase, lowercase, numbers, and symbols'
      };
    }

    return { valid: true };
  }

  /**
   * Calculate password strength (0-100)
   */
  calculatePasswordStrength(password: string): number {
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
   * Generate cryptographically secure random bytes
   */
  generateRandomBytes(length: number): Uint8Array {
    return crypto.getRandomValues(new Uint8Array(length));
  }

  /**
   * Generate IV for specific algorithm
   */
  generateIV(algorithm: EncryptionAlgorithm): string {
    if (algorithm === 'none') return '';

    const strategy = this.strategies.get(algorithm);
    if (!strategy) {
      throw new Error(`Unknown algorithm: ${algorithm}`);
    }

    const ivSize = strategy.getIvSize();
    const iv = this.generateRandomBytes(ivSize);
    return this.arrayBufferToHex(iv);
  }

  /**
   * Generate salt for key derivation
   */
  generateSalt(algorithm: EncryptionAlgorithm): string {
    if (algorithm === 'none') return '';

    const strategy = this.strategies.get(algorithm);
    if (!strategy) {
      throw new Error(`Unknown algorithm: ${algorithm}`);
    }

    const saltSize = strategy.getSaltSize();
    const salt = this.generateRandomBytes(saltSize);
    return this.arrayBufferToHex(salt);
  }

  /**
   * Utility: Convert ArrayBuffer to hex string
   */
  private arrayBufferToHex(buffer: ArrayBuffer | Uint8Array): string {
    const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    return Array.from(bytes)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }
}
