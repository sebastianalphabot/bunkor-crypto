import { IEncryptionStrategy, EncryptionResult, DecryptionParams } from '../encryption-strategy.interface';

/**
 * Dilithium Authenticated Encryption Strategy
 *
 * NOTE: This strategy is currently DISABLED because the pqc-dilithium library
 * uses WASM which is not compatible with Angular's Zone.js.
 *
 * When a pure JavaScript implementation becomes available (e.g., @noble/post-quantum),
 * this strategy can be re-enabled.
 *
 * Algorithm Details:
 * - Dilithium is a post-quantum Digital Signature Algorithm
 * - NIST PQC standardization: CRYSTALS-Dilithium (now ML-DSA)
 * - Quantum-resistant: Secure against attacks from quantum computers
 */
export class DilithiumSignatureStrategy implements IEncryptionStrategy {
  readonly algorithmName = 'Dilithium-Signature';
  readonly isSupported = false; // Disabled due to WASM compatibility issues
  readonly requiresExternalLibrary = true;

  private readonly IV_SIZE = 24;
  private readonly SALT_SIZE = 32;

  private readonly UNAVAILABLE_MESSAGE =
    'Dilithium-Signature is temporarily unavailable. ' +
    'The pqc-dilithium library uses WASM which is not compatible with Angular Zone.js. ' +
    'Please use a different encryption algorithm such as AES-256-GCM or Kyber-KEM.';

  getIvSize(): number {
    return this.IV_SIZE;
  }

  getSaltSize(): number {
    return this.SALT_SIZE;
  }

  async encrypt(
    _data: ArrayBuffer,
    _password: string,
    _saltHex: string,
    _ivHex: string
  ): Promise<EncryptionResult> {
    throw new Error(this.UNAVAILABLE_MESSAGE);
  }

  async decrypt(_params: DecryptionParams): Promise<Blob> {
    throw new Error(this.UNAVAILABLE_MESSAGE);
  }
}
