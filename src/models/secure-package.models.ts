// Wire-format and in-memory models for .lbxpkg package envelopes and ZK recovery key structures.

export interface StrictKdfParams {
  algorithm: 'PBKDF2';
  iterations: number;
  hash: 'SHA-256';
  salt_b64: string;
}

// One entry in file_map payload
export interface FileMapEntry {
  name: string;       // real filename, e.g. "passport.pdf"
  mime: string;       // MIME type, e.g. "application/pdf"
  size: number;       // file size in bytes
  field_id?: string;  // form field this file belongs to — encrypted inside package, ZK-safe
}

// Map of obfuscated storage name → real file info
export type FileMap = Record<string, FileMapEntry>;

// One field from the form submission
export interface FieldEntry {
  field_id: string;
  label: string;
  value: unknown;
}

// Decrypted payload inside a .lbxpkg file
export interface PackagePayload {
  fields: FieldEntry[];
  file_map: FileMap;
}

// The .lbxpkg envelope as stored/transmitted
export interface PackageEnvelope {
  v: number;  // wire-format key name is "v" (not "version") — increment on breaking payload changes
  type: 'submission' | 'folder' | 'vault';
  cek_wrapped: string;        // RSA-OAEP wrapped AES-256 CEK, base64
  payload: string;            // IV(12 bytes) || AES-GCM ciphertext, base64
}

// One recovery code entry (for server storage)
export interface RecoveryCodeEntry {
  hash: string;       // SHA-256(code) as hex string
  blob: string;       // AES-GCM encrypted private key, base64
  kdf_params: StrictKdfParams;
  used: boolean;
}

/** Client-only, in-memory type. Must never be persisted or transmitted — codes are shown once and discarded. */
export interface RecoveryCodeSet {
  codes: string[];              // 8 plaintext codes in "XXXX-XXXX" format — show to user once
  entries: RecoveryCodeEntry[]; // server-side storage objects
}

// SM mode owner recovery key file format
export interface SmRecoveryKeyPackage {
  v: number;                   // version 1
  type: 'sm_recovery_key';
  algorithm: 'RSA-OAEP';
  private_key_pem: string;
  org_id: string;
  exported_at: string;         // ISO 8601
  instructions: string;
}

// Recovery key blob for recovery option 1
export interface RecoveryKeyBlob {
  blob: string;        // AES-GCM encrypted private key, base64
  kdf_params: StrictKdfParams;
}
