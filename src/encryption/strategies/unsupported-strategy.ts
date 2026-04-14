import { IEncryptionStrategy, EncryptionResult, DecryptionParams } from '../encryption-strategy.interface';

/**
 * Base class for unsupported encryption algorithms
 * These require specialized libraries or are experimental
 *
 * SOLID Principles:
 * - Single Responsibility: Handles unsupported algorithm error messaging
 * - Open/Closed: Extensible through inheritance
 * - Liskov Substitution: Can substitute IEncryptionStrategy (throws meaningful errors)
 * - Interface Segregation: Implements focused IEncryptionStrategy
 * - Dependency Inversion: Implements abstraction
 */
export class UnsupportedStrategy implements IEncryptionStrategy {
  readonly isSupported = false;
  readonly requiresExternalLibrary = true;

  constructor(
    public readonly algorithmName: string,
    private readonly libraryName: string,
    private readonly reason: string
  ) {}

  getIvSize(): number {
    throw new Error(`${this.algorithmName} is not supported: ${this.reason}`);
  }

  getSaltSize(): number {
    throw new Error(`${this.algorithmName} is not supported: ${this.reason}`);
  }

  async encrypt(): Promise<EncryptionResult> {
    throw new Error(
      `${this.algorithmName} is not yet supported. ` +
      `Requires external library: ${this.libraryName}. ` +
      `Reason: ${this.reason}`
    );
  }

  async decrypt(): Promise<Blob> {
    throw new Error(
      `${this.algorithmName} is not yet supported. ` +
      `Requires external library: ${this.libraryName}. ` +
      `Reason: ${this.reason}`
    );
  }
}

/**
 * ChaCha20-Poly1305 Strategy (Unsupported - Coming Soon)
 *
 * Modern authenticated encryption algorithm
 * - Faster than AES on devices without hardware AES acceleration
 * - Used in TLS 1.3, WireGuard, Signal Protocol
 * - Requires: libsodium.js (ESM bundling issues with Angular)
 * - NOT available in Web Crypto API
 */
export class ChaCha20Poly1305Strategy extends UnsupportedStrategy {
  constructor() {
    super(
      'ChaCha20-Poly1305',
      'libsodium.js',
      'libsodium.js has ESM module resolution issues with Angular bundler. ' +
      'Use AES-256-GCM for now. ChaCha20 support coming in future release.'
    );
  }
}

/**
 * XChaCha20-Poly1305 Strategy (Unsupported - Coming Soon)
 *
 * Extended nonce variant of ChaCha20-Poly1305
 * - 192-bit nonce instead of 96-bit
 * - Better for random nonces
 * - Requires: libsodium.js
 */
export class XChaCha20Poly1305Strategy extends UnsupportedStrategy {
  constructor() {
    super(
      'XChaCha20-Poly1305',
      'libsodium.js',
      'libsodium.js has ESM module resolution issues with Angular bundler. ' +
      'Use AES-256-GCM for now. XChaCha20 support coming in future release.'
    );
  }
}

/**
 * Kyber-KEM Strategy (Unsupported)
 *
 * Post-Quantum Key Encapsulation Mechanism
 * - Quantum-resistant encryption
 * - NIST PQC standardization finalist
 * - Requires: specialized PQC library
 */
export class KyberKemStrategy extends UnsupportedStrategy {
  constructor() {
    super(
      'Kyber-KEM',
      'pqc-kyber or CRYSTALS-Kyber implementation',
      'Post-quantum cryptography. Not yet standardized or available in Web Crypto API. ' +
      'Requires specialized PQC library and is experimental.'
    );
  }
}

/**
 * Dilithium-Signature Strategy (Unsupported)
 *
 * Post-Quantum Digital Signature
 * - Quantum-resistant signatures
 * - NIST PQC standardization finalist
 * - For signing, not encryption
 * - Requires: specialized PQC library
 */
export class DilithiumSignatureStrategy extends UnsupportedStrategy {
  constructor() {
    super(
      'Dilithium-Signature',
      'CRYSTALS-Dilithium implementation',
      'Post-quantum digital signatures (not encryption). Not yet standardized. ' +
      'Use for signing/verification, not file encryption.'
    );
  }
}
