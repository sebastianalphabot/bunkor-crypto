// ML-KEM types
interface MlKemInstance {
  generateKeyPair(): Promise<[Uint8Array, Uint8Array]>;
  deriveKeyPair(seed: Uint8Array): Promise<[Uint8Array, Uint8Array]>;
  encap(publicKey: Uint8Array): Promise<[Uint8Array, Uint8Array]>;
  decap(ciphertext: Uint8Array, secretKey: Uint8Array): Promise<Uint8Array>;
}

export type EncryptionAlgorithm =
  | 'AES-256-GCM'
  | 'AES-256-CBC'
  | 'AES-256-CTR'
  | 'Kyber-768-AES'
  | 'Kyber-1024-AES'
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

/**
 * Zero-Knowledge Encryption Service
 *
 * Provides client-side encryption/decryption using multiple algorithms.
 * Server NEVER sees decrypted content or encryption keys.
 *
 * Supported Algorithms:
 * - AES-256-GCM (recommended, fast, authenticated)
 * - AES-256-CBC (legacy compatibility)
 * - AES-256-CTR (streaming)
 * - Kyber-768-AES (post-quantum hybrid, ~AES-192 security)
 * - Kyber-1024-AES (post-quantum hybrid, ~AES-256 security)
 *
 * DEPENDENCIES:
 *   pnpm install mlkem
 */
export class EncryptionService {

  private readonly PBKDF2_ITERATIONS = 100000;
  private readonly KEY_LENGTH = 256;

  /**
   * Encrypt a file using the specified algorithm
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

    const fileBuffer = await params.file.arrayBuffer();

    switch (params.algorithm) {
      case 'AES-256-GCM':
        this.validateIvLength(params.iv, 12);
        return await this.encryptAESGCM(fileBuffer, params.password, params.salt, params.iv);

      case 'AES-256-CBC':
        this.validateIvLength(params.iv, 16);
        return await this.encryptAESCBC(fileBuffer, params.password, params.salt, params.iv);

      case 'AES-256-CTR':
        this.validateIvLength(params.iv, 16);
        return await this.encryptAESCTR(fileBuffer, params.password, params.salt, params.iv);

      case 'Kyber-768-AES':
        this.validateIvLength(params.iv, 12);
        return await this.encryptKyberHybrid(fileBuffer, params.password, params.salt, params.iv, 768);

      case 'Kyber-1024-AES':
        this.validateIvLength(params.iv, 12);
        return await this.encryptKyberHybrid(fileBuffer, params.password, params.salt, params.iv, 1024);

      default:
        throw new Error(`Unsupported encryption algorithm: ${params.algorithm}`);
    }
  }

  /**
   * Byte size for resumable upload chunks (5MB)
   * Must match VaultUploadService.CHUNK_SIZE
   */
  private readonly CHUNK_SIZE = 5 * 1024 * 1024;

  /**
   * Decrypt a file using the specified algorithm with progress reporting
   */
  async decryptFile(
    params: DecryptionParams,
    onProgress?: (progress: number) => void
  ): Promise<Blob> {
    if (params.algorithm === 'none') {
      if (onProgress) onProgress(100);
      return params.encryptedBlob;
    }

    const encryptedBlob = params.encryptedBlob;
    const overhead = this.getEncryptionOverhead(params.algorithm);

    // Detect if this is a large file encrypted in chunks
    if (encryptedBlob.size > this.CHUNK_SIZE) {
      const decryptedChunks: Blob[] = [];
      const numChunks = Math.ceil(encryptedBlob.size / this.CHUNK_SIZE);
      const originalChunkSize = this.CHUNK_SIZE - overhead;

      for (let i = 0; i < numChunks; i++) {
        const start = i * this.CHUNK_SIZE;
        const end = Math.min(start + this.CHUNK_SIZE, encryptedBlob.size);
        const chunkBlob = encryptedBlob.slice(start, end);
        const chunkBuffer = await chunkBlob.arrayBuffer();
        
        // Use the same IV increment logic as VaultUploadService.encryptChunk
        const originalOffset = i * originalChunkSize;
        const chunkIv = this.incrementIv(params.iv, originalOffset);
        
        const decryptedChunk = await this.decryptSingleChunk(
          chunkBuffer, 
          params.password, 
          chunkIv, 
          params.salt, 
          params.algorithm
        );
        decryptedChunks.push(decryptedChunk);

        if (onProgress) {
          onProgress(Math.round(((i + 1) / numChunks) * 100));
        }
      }
      
      return new Blob(decryptedChunks);
    }

    // Single chunk decryption
    if (onProgress) onProgress(10); // Start
    const encryptedBuffer = await encryptedBlob.arrayBuffer();
    if (onProgress) onProgress(50); // Buffering done
    const decryptedBlob = await this.decryptSingleChunk(
      encryptedBuffer, 
      params.password, 
      params.iv, 
      params.salt, 
      params.algorithm
    );
    if (onProgress) onProgress(100); // Complete
    return decryptedBlob;
  }

  /**
   * Internal helper to decrypt a single chunk of data
   */
  private async decryptSingleChunk(
    encryptedData: ArrayBuffer,
    password: string,
    ivHex: string,
    saltHex: string,
    algorithm: EncryptionAlgorithm
  ): Promise<Blob> {
    switch (algorithm) {
      case 'AES-256-GCM':
        return await this.decryptAESGCM(encryptedData, password, ivHex, saltHex);

      case 'AES-256-CBC':
        return await this.decryptAESCBC(encryptedData, password, ivHex, saltHex);

      case 'AES-256-CTR':
        return await this.decryptAESCTR(encryptedData, password, ivHex, saltHex);

      case 'Kyber-768-AES':
      case 'Kyber-1024-AES':
        return await this.decryptKyberHybrid(
          encryptedData,
          password,
          ivHex,
          saltHex,
          algorithm === 'Kyber-1024-AES' ? 1024 : 768
        );

      default:
        throw new Error(`Unsupported decryption algorithm: ${algorithm}`);
    }
  }

  /**
   * Increments an IV based on a byte offset.
   * Ensures different chunks use different nonces to avoid security vulnerabilities.
   */
  public incrementIv(ivHex: string, offset: number): string {
    const iv = this.hexToUint8Array(ivHex);
    // Offset is in bytes. Counter increments every 16 bytes for AES.
    // For GCM nonces (12 bytes), we still increment the whole nonce as a counter.
    const counterIncrement = Math.floor(offset / 16);
    let carry = counterIncrement;
    
    for (let i = iv.length - 1; i >= 0 && carry > 0; i--) {
      const sum = iv[i] + (carry & 0xff);
      iv[i] = sum & 0xff;
      carry = (carry >> 8) + (sum >> 8);
    }
    
    return this.arrayBufferToHex(iv);
  }

  /**
   * Get the required IV/nonce size for each algorithm
   */
  getIvSizeForAlgorithm(algorithm: EncryptionAlgorithm): number {
    switch (algorithm) {
      case 'AES-256-GCM':
      case 'Kyber-768-AES':
      case 'Kyber-1024-AES':
        return 12;
      case 'AES-256-CBC':
      case 'AES-256-CTR':
        return 16;
      default:
        return 16;
    }
  }

  /**
   * Get the byte overhead added by the encryption algorithm
   */
  getEncryptionOverhead(algorithm: EncryptionAlgorithm): number {
    switch (algorithm) {
      case 'AES-256-GCM':
        return 16; // Authentication tag
      case 'AES-256-CBC':
        return 16; // Max PKCS#7 padding
      case 'AES-256-CTR':
        return 0;  // Stream cipher, no overhead
      case 'Kyber-768-AES':
        return 1088 + 16; // KEM ciphertext + AES-GCM tag
      case 'Kyber-1024-AES':
        return 1568 + 16; // KEM ciphertext + AES-GCM tag
      case 'none':
        return 0;
      default:
        return 0;
    }
  }

  private validateIvLength(ivHex: string, expectedBytes: number): void {
    const actualBytes = ivHex.length / 2;
    if (actualBytes !== expectedBytes) {
      throw new Error(`Expected ${expectedBytes}-byte IV, got ${actualBytes} bytes`);
    }
  }

  validatePassword(password: string): { valid: boolean; message?: string } {
    if (!password) {
      return { valid: false, message: 'Password is required' };
    }

    if (password.length < 8) {
      return { valid: false, message: 'Password must be at least 8 characters long' };
    }

    // Check complexity requirements: at least one uppercase, one lowercase, one number, and one special character
    const hasUppercase = /[A-Z]/.test(password);
    const hasLowercase = /[a-z]/.test(password);
    const hasNumber = /[0-9]/.test(password);
    const hasSpecial = /[^A-Za-z0-9]/.test(password);

    if (!hasUppercase || !hasLowercase || !hasNumber || !hasSpecial) {
      return {
        valid: false,
        message: 'Password must include uppercase, lowercase, number, and special character'
      };
    }

    return { valid: true };
  }

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

  // ============================================================================
  // ML-KEM (Kyber) Loading
  // ============================================================================

  private async loadMlKem(securityLevel: 768 | 1024): Promise<MlKemInstance> {
    try {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const mlkemModule: any = await import('mlkem');
      const MlKemClass = securityLevel === 1024
        ? mlkemModule.MlKem1024
        : mlkemModule.MlKem768;
      return new MlKemClass();
    } catch (error) {
      throw new Error(
        'Failed to load mlkem. Please install: pnpm install mlkem'
      );
    }
  }

  // ============================================================================
  // AES-256-GCM (Web Crypto API) - RECOMMENDED
  // ============================================================================

  private async encryptAESGCM(
    data: ArrayBuffer,
    password: string,
    saltHex: string,
    ivHex: string
  ): Promise<EncryptionResult> {
    const key = await this.deriveKey(password, saltHex, 'AES-GCM');
    const iv = this.hexToArrayBuffer(ivHex);

    const encryptedBuffer = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      data
    );

    return {
      encryptedBlob: new Blob([encryptedBuffer]),
      iv: ivHex,
      algorithm: 'AES-256-GCM',
      salt: saltHex
    };
  }

  private async decryptAESGCM(
    encryptedData: ArrayBuffer,
    password: string,
    ivHex: string,
    saltHex: string
  ): Promise<Blob> {
    const key = await this.deriveKey(password, saltHex, 'AES-GCM');
    const iv = this.hexToArrayBuffer(ivHex);

    try {
      const decryptedBuffer = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv },
        key,
        encryptedData
      );

      return new Blob([decryptedBuffer]);
    } catch {
      throw new Error('Decryption failed. Please check your password.');
    }
  }

  // ============================================================================
  // AES-256-CBC (Web Crypto API)
  // ============================================================================

  private async encryptAESCBC(
    data: ArrayBuffer,
    password: string,
    saltHex: string,
    ivHex: string
  ): Promise<EncryptionResult> {
    const key = await this.deriveKey(password, saltHex, 'AES-CBC');
    const iv = this.hexToArrayBuffer(ivHex);

    const encryptedBuffer = await crypto.subtle.encrypt(
      { name: 'AES-CBC', iv },
      key,
      data
    );

    return {
      encryptedBlob: new Blob([encryptedBuffer]),
      iv: ivHex,
      algorithm: 'AES-256-CBC',
      salt: saltHex
    };
  }

  private async decryptAESCBC(
    encryptedData: ArrayBuffer,
    password: string,
    ivHex: string,
    saltHex: string
  ): Promise<Blob> {
    const key = await this.deriveKey(password, saltHex, 'AES-CBC');
    const iv = this.hexToArrayBuffer(ivHex);

    try {
      const decryptedBuffer = await crypto.subtle.decrypt(
        { name: 'AES-CBC', iv },
        key,
        encryptedData
      );

      return new Blob([decryptedBuffer]);
    } catch {
      throw new Error('Decryption failed. Please check your password.');
    }
  }

  // ============================================================================
  // AES-256-CTR (Web Crypto API)
  // ============================================================================

  private async encryptAESCTR(
    data: ArrayBuffer,
    password: string,
    saltHex: string,
    ivHex: string
  ): Promise<EncryptionResult> {
    const key = await this.deriveKey(password, saltHex, 'AES-CTR');
    const counter = this.hexToArrayBuffer(ivHex);

    const encryptedBuffer = await crypto.subtle.encrypt(
      { name: 'AES-CTR', counter, length: 64 },
      key,
      data
    );

    return {
      encryptedBlob: new Blob([encryptedBuffer]),
      iv: ivHex,
      algorithm: 'AES-256-CTR',
      salt: saltHex
    };
  }

  private async decryptAESCTR(
    encryptedData: ArrayBuffer,
    password: string,
    ivHex: string,
    saltHex: string
  ): Promise<Blob> {
    const key = await this.deriveKey(password, saltHex, 'AES-CTR');
    const counter = this.hexToArrayBuffer(ivHex);

    try {
      const decryptedBuffer = await crypto.subtle.decrypt(
        { name: 'AES-CTR', counter, length: 64 },
        key,
        encryptedData
      );

      return new Blob([decryptedBuffer]);
    } catch {
      throw new Error('Decryption failed. Please check your password.');
    }
  }

  // ============================================================================
  // Kyber Hybrid Encryption (ML-KEM + AES-256-GCM) - POST-QUANTUM
  // ============================================================================

  private async encryptKyberHybrid(
    data: ArrayBuffer,
    password: string,
    saltHex: string,
    ivHex: string,
    securityLevel: 768 | 1024
  ): Promise<EncryptionResult> {
    const mlkem = await this.loadMlKem(securityLevel);

    // Derive deterministic keypair from password + salt
    const seed = await this.deriveKyberSeed(password, saltHex);
    const [publicKey] = await mlkem.deriveKeyPair(seed);

    // Encapsulate: generates shared secret + KEM ciphertext bound to public key
    const [kemCiphertext, sharedSecret] = await mlkem.encap(publicKey);

    // Use shared secret as AES-256-GCM key
    const aesKey = await crypto.subtle.importKey(
      'raw',
      this.uint8ArrayToArrayBuffer(sharedSecret.slice(0, 32)),
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt']
    );

    const iv = this.hexToArrayBuffer(ivHex);

    const encryptedBuffer = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      aesKey,
      data
    );

    // Prepend KEM ciphertext to encrypted data
    // Format: [KEM ciphertext] + [AES-GCM encrypted data]
    const combined = new Uint8Array(kemCiphertext.length + encryptedBuffer.byteLength);
    combined.set(kemCiphertext, 0);
    combined.set(new Uint8Array(encryptedBuffer), kemCiphertext.length);

    return {
      encryptedBlob: new Blob([combined]),
      iv: ivHex,
      algorithm: securityLevel === 1024 ? 'Kyber-1024-AES' : 'Kyber-768-AES',
      salt: saltHex
    };
  }

  private async decryptKyberHybrid(
    encryptedData: ArrayBuffer,
    password: string,
    ivHex: string,
    saltHex: string,
    securityLevel: 768 | 1024
  ): Promise<Blob> {
    const mlkem = await this.loadMlKem(securityLevel);

    // Re-derive the same deterministic keypair from password + salt
    const seed = await this.deriveKyberSeed(password, saltHex);
    const [, secretKey] = await mlkem.deriveKeyPair(seed);

    // KEM ciphertext sizes are fixed by the spec
    const kemCiphertextSize = securityLevel === 768 ? 1088 : 1568;

    const combined = new Uint8Array(encryptedData);
    if (combined.length < kemCiphertextSize) {
      throw new Error('Invalid encrypted data: too short for Kyber ciphertext');
    }

    // Extract KEM ciphertext (prepended) and AES-GCM payload
    const kemCiphertext = combined.slice(0, kemCiphertextSize);
    const aesEncryptedData = combined.slice(kemCiphertextSize);

    // Decapsulate: recover shared secret using secret key + KEM ciphertext
    const sharedSecret = await mlkem.decap(kemCiphertext, secretKey);

    // Use shared secret as AES-256-GCM key (same derivation as encrypt)
    const aesKey = await crypto.subtle.importKey(
      'raw',
      this.uint8ArrayToArrayBuffer(sharedSecret.slice(0, 32)),
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt']
    );

    const iv = this.hexToArrayBuffer(ivHex);

    try {
      const decryptedBuffer = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv },
        aesKey,
        aesEncryptedData
      );

      return new Blob([decryptedBuffer]);
    } catch {
      throw new Error('Decryption failed. Please check your password.');
    }
  }

  // ============================================================================
  // Key Derivation (PBKDF2)
  // ============================================================================

  private async deriveKey(
    password: string,
    saltHex: string,
    algorithm: 'AES-GCM' | 'AES-CBC' | 'AES-CTR'
  ): Promise<CryptoKey> {
    const passwordBuffer = new TextEncoder().encode(password);
    const salt = this.hexToArrayBuffer(saltHex);

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
        salt,
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
   * Derive a 64-byte seed for ML-KEM deterministic keypair generation.
   * Same password + salt always produces the same seed → same keypair.
   */
  private async deriveKyberSeed(password: string, saltHex: string): Promise<Uint8Array> {
    const passwordBuffer = new TextEncoder().encode(password);
    const salt = this.hexToArrayBuffer(saltHex);

    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      passwordBuffer,
      'PBKDF2',
      false,
      ['deriveBits']
    );

    const seedBits = await crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt,
        iterations: this.PBKDF2_ITERATIONS,
        hash: 'SHA-256'
      },
      keyMaterial,
      512 // 64 bytes — required by ML-KEM deriveKeyPair
    );

    return new Uint8Array(seedBits);
  }

  // ============================================================================
  // Utility Functions
  // ============================================================================

  private uint8ArrayToArrayBuffer(arr: Uint8Array): ArrayBuffer {
    const buffer = new ArrayBuffer(arr.length);
    const view = new Uint8Array(buffer);
    view.set(arr);
    return buffer;
  }

  private arrayBufferToHex(buffer: ArrayBuffer | Uint8Array): string {
    const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    return Array.from(bytes)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }

  private hexToArrayBuffer(hex: string): ArrayBuffer {
    if (!/^[0-9a-fA-F]*$/.test(hex)) {
      throw new Error('Invalid hex string: contains non-hex characters');
    }
    if (hex.length % 2 !== 0) {
      throw new Error('Invalid hex string: length must be even');
    }

    const length = hex.length / 2;
    const buffer = new ArrayBuffer(length);
    const view = new Uint8Array(buffer);

    for (let i = 0; i < length; i++) {
      view[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
    }

    return buffer;
  }

  private hexToUint8Array(hex: string): Uint8Array {
    return new Uint8Array(this.hexToArrayBuffer(hex));
  }
}
