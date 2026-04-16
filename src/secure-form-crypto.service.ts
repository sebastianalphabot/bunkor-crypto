import { Injectable } from '@angular/core';
import { EncFileJson, KdfParams } from './models/secure-forms.models';

/**
 * SecureFormCryptoService
 *
 * Owns ALL Web Crypto API calls for secure-form encryption.
 * No HTTP calls. No business logic. CryptoKey objects never leave this service as raw bytes.
 */
@Injectable({ providedIn: 'root' })
export class SecureFormCryptoService {

  // ─── CEK (Content Encryption Key) ────────────────────────────────────────

  generateCEK(): Promise<CryptoKey> {
    return crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );
  }

  /**
   * Encrypt arbitrary data with the CEK.
   * Output format: 12-byte IV || ciphertext
   */
  async encryptWithCEK(cek: CryptoKey, data: ArrayBuffer): Promise<Uint8Array<ArrayBuffer>> {
    const iv = this._randomBytes(12);
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, cek, data);
    const buf = new ArrayBuffer(12 + ciphertext.byteLength);
    const result = new Uint8Array(buf);
    result.set(iv, 0);
    result.set(new Uint8Array(ciphertext), 12);
    return result;
  }

  /**
   * Decrypt data previously encrypted by encryptWithCEK.
   * Expects input format: 12-byte IV || ciphertext
   */
  async decryptWithCEK(cek: CryptoKey, blob: Uint8Array): Promise<ArrayBuffer> {
    const iv = this._fromBuffer(blob.buffer as ArrayBuffer, blob.byteOffset, 12);
    const ciphertext = this._fromBuffer(blob.buffer as ArrayBuffer, blob.byteOffset + 12);
    return crypto.subtle.decrypt({ name: 'AES-GCM', iv }, cek, ciphertext);
  }

  /**
   * Wrap the CEK with an RSA-OAEP public key (PEM).
   * Returns base64 string.
   */
  async wrapCEK(cek: CryptoKey, publicKeyPem: string): Promise<string> {
    const publicKey = await this._importPublicKeyPem(publicKeyPem);
    const wrapped = await crypto.subtle.wrapKey('raw', cek, publicKey, { name: 'RSA-OAEP' });
    return this._toBase64(new Uint8Array(wrapped));
  }

  /**
   * Unwrap a base64-encoded wrapped CEK using an RSA-OAEP private key.
   */
  async unwrapCEK(wrappedB64: string, privateKey: CryptoKey): Promise<CryptoKey> {
    const wrappedBytes = this._fromBase64(wrappedB64);
    return crypto.subtle.unwrapKey(
      'raw',
      wrappedBytes,
      privateKey,
      { name: 'RSA-OAEP' },
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );
  }

  // ─── Zero-Knowledge (ZK) mode ─────────────────────────────────────────────

  /**
   * Generate an RSA-4096 keypair for ZK mode.
   * Returns public key as PEM and the private CryptoKey (in-memory only).
   */
  async generateKeyPair(): Promise<{ publicKeyPem: string; privateKey: CryptoKey }> {
    const { publicKey, privateKey } = await crypto.subtle.generateKey(
      {
        name: 'RSA-OAEP',
        modulusLength: 4096,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256',
      },
      true,
      ['wrapKey', 'unwrapKey']
    );
    const publicKeyPem = await this._exportPublicKeyPem(publicKey);
    return { publicKeyPem, privateKey };
  }

  /**
   * Encrypt the private key with a user password using PBKDF2 → AES-GCM.
   * Returns the encrypted blob (base64) and the KDF params needed for later decryption.
   * The password is used once and discarded — never stored.
   */
  async encryptPrivateKey(
    privateKey: CryptoKey,
    password: string
  ): Promise<{ blob: string; kdfParams: KdfParams }> {
    const salt = this._randomBytes(16);
    const aesKey = await this._deriveAesKey(password, salt, ['encrypt']);

    const privateKeyBytes = await crypto.subtle.exportKey('pkcs8', privateKey);
    const iv = this._randomBytes(12);
    const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, privateKeyBytes);

    const buf = new ArrayBuffer(12 + encrypted.byteLength);
    const blobBytes = new Uint8Array(buf);
    blobBytes.set(iv, 0);
    blobBytes.set(new Uint8Array(encrypted), 12);

    return {
      blob: this._toBase64(blobBytes),
      kdfParams: {
        algorithm: 'PBKDF2',
        iterations: 600000,
        hash: 'SHA-256',
        salt_b64: this._toBase64(salt),
      },
    };
  }

  /**
   * Decrypt the private key blob with the user's password and KDF params.
   * Returns an in-memory CryptoKey. Password is used once and discarded.
   */
  async decryptPrivateKey(
    blob: string,
    password: string,
    kdfParams: KdfParams
  ): Promise<CryptoKey> {
    const salt = this._fromBase64(kdfParams.salt_b64);
    const aesKey = await this._deriveAesKey(password, salt, ['decrypt'], kdfParams);

    const blobBytes = this._fromBase64(blob);
    const iv = this._fromBuffer(blobBytes.buffer, 0, 12);
    const ciphertext = this._fromBuffer(blobBytes.buffer, 12);
    const privateKeyBytes = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, ciphertext);

    return crypto.subtle.importKey(
      'pkcs8',
      privateKeyBytes,
      { name: 'RSA-OAEP', hash: 'SHA-256' },
      false,
      ['decrypt', 'unwrapKey']
    );
  }

  // ─── Server-Managed (SM) mode ─────────────────────────────────────────────

  /**
   * Import a PEM-encoded RSA private key (SM mode — fetched from server, never cached).
   * Imported with both 'decrypt' (for .enc files) and 'unwrapKey' (for CEK unwrapping).
   */
  importPrivateKeyPem(pem: string): Promise<CryptoKey> {
    const isPkcs1 = /BEGIN RSA PRIVATE KEY/.test(pem);
    // Use _fromBase64 directly (returns Uint8Array) rather than _pemToDer (returns .buffer)
    // so Node.js SubtleCrypto accepts it without an instanceof ArrayBuffer realm mismatch.
    const derBytes = this._fromBase64(
      pem
        .replace(/-----BEGIN [^-]+-----/, '')
        .replace(/-----END [^-]+-----/, '')
        .replace(/\s+/g, '')
    );
    const pkcs8Der = isPkcs1 ? this._wrapPkcs1ToPkcs8(derBytes) : derBytes;
    return crypto.subtle.importKey(
      'pkcs8',
      pkcs8Der,
      { name: 'RSA-OAEP', hash: 'SHA-256' },
      false,
      ['decrypt', 'unwrapKey']
    );
  }

  // ─── .enc file decryption ─────────────────────────────────────────────────

  /**
   * Decrypt a backend-produced .enc file.
   *
   * .enc files are JSON blobs with the shape:
   *   { version, encrypted, cek_encrypted_b64, iv_b64, ciphertext_b64, tag_b64 }
   *
   * Algorithm:
   *   1. RSA-OAEP decrypt cek_encrypted_b64 → raw AES-256 CEK bytes
   *   2. Import raw bytes as AES-GCM key
   *   3. Concatenate ciphertext_b64 + tag_b64
   *   4. AES-GCM decrypt with iv_b64 → plaintext
   *
   * @param encBytes  Raw bytes of the .enc file (UTF-8 JSON)
   * @param privateKey  RSA-OAEP private key imported with the 'decrypt' usage
   */
  async decryptEncFile(encBytes: Uint8Array, privateKey: CryptoKey): Promise<ArrayBuffer> {
    const json: EncFileJson = JSON.parse(new TextDecoder().decode(encBytes));
    const { cek_encrypted_b64, iv_b64, ciphertext_b64, tag_b64 } = json;

    // 1. Decrypt CEK
    const rawCek = await crypto.subtle.decrypt(
      { name: 'RSA-OAEP' },
      privateKey,
      this._fromBase64(cek_encrypted_b64)
    );

    // 2. Import AES-GCM key
    const aesKey = await crypto.subtle.importKey(
      'raw',
      rawCek,
      { name: 'AES-GCM' },
      false,
      ['decrypt']
    );

    // 3. Concatenate ciphertext + GCM tag (Web Crypto expects them joined)
    const ct = this._fromBase64(ciphertext_b64);
    const tag = this._fromBase64(tag_b64);
    const combinedBuf = new ArrayBuffer(ct.byteLength + tag.byteLength);
    const combined = new Uint8Array(combinedBuf);
    combined.set(ct, 0);
    combined.set(tag, ct.byteLength);

    // 4. Decrypt — pass the Uint8Array (not the backing ArrayBuffer) to avoid
    // jsdom-realm / Node.js-realm instanceof mismatch in test environments.
    return crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: this._fromBase64(iv_b64) },
      aesKey,
      combined
    );
  }

  // ─── Private helpers ──────────────────────────────────────────────────────

  private async _importPublicKeyPem(pem: string): Promise<CryptoKey> {
    const derBytes = this._fromBase64(
      pem
        .replace(/-----BEGIN [^-]+-----/, '')
        .replace(/-----END [^-]+-----/, '')
        .replace(/\s+/g, '')
    );
    return crypto.subtle.importKey(
      'spki',
      derBytes,
      { name: 'RSA-OAEP', hash: 'SHA-256' },
      false,
      ['wrapKey']
    );
  }

  private async _exportPublicKeyPem(key: CryptoKey): Promise<string> {
    const exported = await crypto.subtle.exportKey('spki', key);
    return `-----BEGIN PUBLIC KEY-----\n${this._toBase64(new Uint8Array(exported))}\n-----END PUBLIC KEY-----`;
  }

  private async _deriveAesKey(
    password: string,
    salt: Uint8Array<ArrayBuffer>,
    usages: KeyUsage[],
    params?: KdfParams
  ): Promise<CryptoKey> {
    const iterations = params?.iterations ?? 600000;
    const hash = params?.hash ?? 'SHA-256';
    const passwordKey = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(password),
      'PBKDF2',
      false,
      ['deriveKey']
    );
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations, hash },
      passwordKey,
      { name: 'AES-GCM', length: 256 },
      false,
      usages
    );
  }

  /** Create a new ArrayBuffer-backed Uint8Array with random bytes. */
  private _randomBytes(length: number): Uint8Array<ArrayBuffer> {
    const buf = new ArrayBuffer(length);
    const view = new Uint8Array(buf);
    crypto.getRandomValues(view);
    return view;
  }

  /** Slice a view out of a known-ArrayBuffer buffer. */
  private _fromBuffer(buf: ArrayBuffer, offset: number, length?: number): Uint8Array<ArrayBuffer> {
    return new Uint8Array(buf, offset, length) as Uint8Array<ArrayBuffer>;
  }

  private _pemToDer(pem: string): ArrayBuffer {
    return this._fromBase64(
      pem
        .replace(/-----BEGIN [^-]+-----/, '')
        .replace(/-----END [^-]+-----/, '')
        .replace(/\s+/g, '')
    ).buffer;
  }

  private _wrapPkcs1ToPkcs8(pkcs1Der: Uint8Array): Uint8Array<ArrayBuffer> {
    const version = this._asn1Integer(0);
    const algorithmId = this._asn1Sequence(
      this._asn1Oid([1, 2, 840, 113549, 1, 1, 1]),
      this._asn1Null()
    );
    const privateKey = this._asn1OctetString(pkcs1Der);
    return this._asn1Sequence(version, algorithmId, privateKey);
  }

  private _asn1Sequence(...children: Uint8Array[]): Uint8Array<ArrayBuffer> {
    const content = this._concatBytes(...children);
    return this._asn1Tag(0x30, content);
  }

  private _asn1Integer(value: number): Uint8Array<ArrayBuffer> {
    if (value === 0) {
      return this._asn1Tag(0x02, new Uint8Array([0x00]));
    }
    const bytes: number[] = [];
    let v = value;
    while (v > 0) {
      bytes.unshift(v & 0xff);
      v >>= 8;
    }
    if (bytes[0] & 0x80) bytes.unshift(0x00);
    return this._asn1Tag(0x02, new Uint8Array(bytes));
  }

  private _asn1Oid(oid: number[]): Uint8Array<ArrayBuffer> {
    const [first, second, ...rest] = oid;
    const bytes: number[] = [40 * first + second];
    for (const part of rest) {
      const enc: number[] = [];
      let v = part;
      enc.unshift(v & 0x7f);
      v >>= 7;
      while (v > 0) {
        enc.unshift((v & 0x7f) | 0x80);
        v >>= 7;
      }
      bytes.push(...enc);
    }
    return this._asn1Tag(0x06, new Uint8Array(bytes));
  }

  private _asn1Null(): Uint8Array<ArrayBuffer> {
    return this._asn1Tag(0x05, new Uint8Array([]));
  }

  private _asn1OctetString(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
    return this._asn1Tag(0x04, bytes);
  }

  private _asn1Tag(tag: number, content: Uint8Array): Uint8Array<ArrayBuffer> {
    return this._concatBytes(new Uint8Array([tag]), this._asn1Length(content.length), content);
  }

  private _asn1Length(length: number): Uint8Array<ArrayBuffer> {
    if (length < 0x80) return new Uint8Array([length]);
    const bytes: number[] = [];
    let v = length;
    while (v > 0) {
      bytes.unshift(v & 0xff);
      v >>= 8;
    }
    return new Uint8Array([0x80 | bytes.length, ...bytes]);
  }

  private _concatBytes(...parts: Uint8Array[]): Uint8Array<ArrayBuffer> {
    const total = parts.reduce((sum, p) => sum + p.length, 0);
    const out = new Uint8Array(new ArrayBuffer(total));
    let offset = 0;
    for (const part of parts) {
      out.set(part, offset);
      offset += part.length;
    }
    return out;
  }

  private _toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
    const buf = new ArrayBuffer(bytes.byteLength);
    new Uint8Array(buf).set(bytes);
    return buf;
  }

  private _toBase64(bytes: Uint8Array): string {
    return btoa(String.fromCharCode(...bytes));
  }

  private _fromBase64(b64: string): Uint8Array<ArrayBuffer> {
    const raw = atob(b64);
    const buf = new ArrayBuffer(raw.length);
    const view = new Uint8Array(buf);
    for (let i = 0; i < raw.length; i++) {
      view[i] = raw.charCodeAt(i);
    }
    return view;
  }
}
