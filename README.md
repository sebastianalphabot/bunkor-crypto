# @bunkor/crypto

Zero-knowledge cryptographic utilities for secure file and form encryption. Enterprise-grade client-side encryption with integration for Bunkor secure storage.

## Features

- Zero-Knowledge Architecture — Encryption/decryption happens entirely on the client. Server never sees plaintext or encryption keys.
- Multiple Algorithms — AES-256-GCM (recommended), AES-256-CBC, AES-256-CTR, post-quantum Kyber-768/1024
- NIST-Approved Crypto — Uses Web Crypto API and only audited, standardized algorithms
- Strong Key Derivation — PBKDF2 with 600K iterations
- Zero-Knowledge Forms — RSA-4096-OAEP key wrapping for end-to-end encryption
- Bunkor Integration — Upload/download encrypted files with automatic key management
- Post-Quantum Support — ML-KEM (Kyber) hybrid encryption
- TypeScript — Fully typed, strict mode compliant
- Apache 2.0 Licensed
- No External Dependencies — Uses native Web Crypto API

## Installation

```bash
# Using npm
npm install @bunkor/crypto

# Using pnpm
pnpm add @bunkor/crypto

# Using yarn
yarn add @bunkor/crypto
```

### Requirements

- **Node.js** 18+ or modern browser with Web Crypto API support
- **Browsers:** Chrome 37+, Firefox 34+, Safari 11+, Edge 79+
- **Angular** 21+ (optional, if using as Angular service)

### Optional Dependencies

- **mlkem** — Installed automatically for ML-KEM/Kyber support

## Quick Start

### Password Hashing

```typescript
import { CryptoService } from '@bunkor/crypto';

const cryptoService = new CryptoService();

// Hash a password
const { hash, salt } = await cryptoService.hashPassword('user-password');

// Verify password
const isValid = await cryptoService.verifyPassword(
  'user-password',
  hash,
  salt
);
```

### File Encryption

```typescript
import { EncryptionService } from '@bunkor/crypto';

const encryptionService = new EncryptionService();

// Encrypt a file
const encrypted = await encryptionService.encryptFile({
  file: blobOrFile,
  password: 'encryption-password',
  algorithm: 'AES-256-GCM',
  salt: 'hex-encoded-salt',
  iv: 'hex-encoded-iv'
});

// Decrypt a file
const decrypted = await encryptionService.decryptFile({
  encryptedBlob: encrypted.encryptedBlob,
  password: 'encryption-password',
  algorithm: 'AES-256-GCM',
  salt: encrypted.salt,
  iv: encrypted.iv
});
```

### Secure Form Encryption (Zero-Knowledge Mode)

```typescript
import { SecureFormCryptoService } from '@bunkor/crypto';

const formCrypto = new SecureFormCryptoService();

// Generate an RSA-4096 keypair for zero-knowledge mode
const { publicKeyPem, privateKey } = await formCrypto.generateKeyPair();

// Encrypt form data with CEK
const cek = await formCrypto.generateCEK();
const encrypted = await formCrypto.encryptWithCEK(
  cek,
  new TextEncoder().encode(formData)
);

// Wrap CEK with public key (send to server)
const wrappedCek = await formCrypto.wrapCEK(cek, publicKeyPem);

// Decrypt private key with password
const { blob, kdfParams } = await formCrypto.encryptPrivateKey(
  privateKey,
  'user-password'
);
```

## Bunkor Integration

This library provides client-side encryption that integrates seamlessly with Bunkor secure storage.

### How It Works

```
User App / Frontend
    ↓
@bunkor/crypto (Client-side encryption)
    ├─ Encrypts file with AES-256-GCM
    ├─ Derives key from password (PBKDF2)
    └─ Generates random salt & IV
    ↓
Bunkor API (https://api.bunkor.io)
    ├─ Receives encrypted file
    ├─ Stores encrypted data (never sees plaintext)
    ├─ Stores salt & IV metadata
    └─ Returns file ID & encryption metadata
    ↓
User retrieves file later
    ├─ Downloads encrypted file + metadata
    ├─ @bunkor/crypto decrypts with password
    └─ Original file recovered
```

### Communication Flow

**Upload:**
1. User selects file and enters password
2. `BunkorClient.uploadEncrypted()` encrypts locally
3. Only encrypted file sent to Bunkor API
4. Server stores: encrypted blob, salt, IV, algorithm
5. Returns file ID for later access

**Download:**
1. App requests file by ID from Bunkor API
2. Server returns: encrypted blob + metadata (salt, IV, algorithm)
3. `BunkorClient.downloadDecrypted()` decrypts locally
4. User gets original file, server never decrypts

### Bunkor Links

- **Bunkor Frontend:** https://beta.bunkor.com
- **API Documentation:** https://docs.bunkor.com
- **API Endpoint:** https://api.bunkor.io

### Example: Full Bunkor Workflow

```typescript
import { BunkorClient } from '@bunkor/crypto';

// Initialize with Bunkor credentials
const bunkor = new BunkorClient({
  apiUrl: 'https://api.bunkor.io',
  apiToken: process.env.BUNKOR_TOKEN,
});

// Upload to Bunkor (encrypted)
const result = await bunkor.uploadEncrypted(
  userFile,
  userPassword,
  'AES-256-GCM'
);
console.log('File ID:', result.fileId); // Store this

// Later: Download from Bunkor (decrypted)
const decrypted = await bunkor.downloadDecrypted(
  result.fileId,
  userPassword,
  (progress) => console.log(`${progress}%`)
);

// Bunkor API never sees unencrypted content
// All encryption/decryption happens in browser
```

### Security Model

- Bunkor stores encrypted data (cannot read without decryption)
- Decryption key derived from user password (only user knows it)
- Server enforces access control on encrypted files
- Audit trail logs who accessed encrypted files and when
- User can safely share file IDs; decryption requires correct password

## Supported Algorithms

### Standard Encryption

| Algorithm | Key Size | Mode | IV Size | Speed | Security |
|-----------|----------|------|---------|-------|----------|
| AES-256-GCM | 256-bit | Authenticated | 96-bit | Fast | Recommended |
| AES-256-CBC | 256-bit | Unauthenticated | 128-bit | Fast | Legacy |
| AES-256-CTR | 256-bit | Stream | 128-bit | Fast | Optional |

### Post-Quantum Hybrid

| Algorithm | KEM | Security | Use Case |
|-----------|-----|----------|----------|
| Kyber-768-AES | ML-KEM 768 | ~AES-192 | Most use cases |
| Kyber-1024-AES | ML-KEM 1024 | ~AES-256 | High-security |

## Architecture

### Services

#### CryptoService
- Password hashing using PBKDF2
- Secure random salt generation
- Zero-knowledge password verification

#### EncryptionService
- Multi-algorithm file encryption/decryption
- Supports chunked encryption for large files
- Progress reporting
- IV/nonce management

#### SecureFormCryptoService
- RSA-4096 keypair generation
- Content Encryption Key (CEK) management
- Private key encryption with PBKDF2 + AES-GCM
- .enc file format handling
- ASN.1 encoding for PKCS#1 to PKCS#8 conversion

#### KeyringEncryptionService
- Multi-key encryption/decryption
- Key rotation support
- Keyring management

## Zero-Knowledge Guarantee

This library ensures:
1. **Client-side encryption** — All cryptographic operations happen in the browser
2. **Key isolation** — Encryption keys never leave the client
3. **No key transmission** — Only encrypted data and public keys are sent to server
4. **Password-based derivation** — Keys derived from user passwords, never stored
5. **Standard algorithms** — Uses NIST-approved, audited cryptography

## Security Considerations

⚠️ **Important**

- This library provides **client-side encryption only**. Implement proper:
  - Key management on the server
  - Access control enforcement
  - Audit logging
  - Key backup/recovery procedures
- Keys are derived from passwords using PBKDF2 with 600K iterations. Use **strong passwords**.
- For production use, validate that the server properly enforces access control.

## Performance Tips

### Large Files

For files >5MB, use chunked encryption:

```typescript
// EncryptionService automatically detects large files
// and encrypts in 5MB chunks with proper IV derivation
const decrypted = await encryptionService.decryptFile(
  params,
  (progress) => console.log(`${progress}% complete`)
);
```

### Algorithm Selection

- **AES-256-GCM** (recommended) — Fastest, authenticated
- **Kyber-768-AES** — If you need post-quantum security
- **AES-256-CBC** — Legacy compatibility only

## Browser Support

Requires Web Crypto API support:
- Chrome 37+
- Firefox 34+
- Safari 11+
- Edge 79+

## Building

```bash
npm run build  # Compiles TypeScript to dist/
npm run test   # Runs tests
npm run lint   # Lints code
```

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.

## Contributing

Contributions welcome! Please ensure:
- All tests pass
- Code is TypeScript strict mode compliant
- No custom cryptography (use standard algorithms only)
- Security review for any changes to crypto code

## Support

For issues, questions, or security concerns, please file an issue at:
https://github.com/bunkor/bunkor-crypto/issues
