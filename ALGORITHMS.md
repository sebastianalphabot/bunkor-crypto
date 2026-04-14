# Cryptographic Algorithms Used in @bunkor/crypto

This document provides comprehensive details about all cryptographic algorithms, their security properties, and recommended use cases.

## Overview

`@bunkor/crypto` uses **only NIST-approved, audited cryptographic algorithms**. No proprietary or experimental cryptography.

| Algorithm | Type | Key Size | Security Level | Use Case |
|-----------|------|----------|----------------|----------|
| **AES-256-GCM** | Symmetric Encryption | 256-bit |  | **Recommended for all use cases** |
| **AES-256-CBC** | Symmetric Encryption | 256-bit |  | Legacy compatibility |
| **AES-256-CTR** | Stream Cipher | 256-bit |  | Large files, streaming |
| **ML-KEM (Kyber)** | Post-Quantum KEM | 768/1024 |  | Future-proofing |
| **RSA-OAEP** | Asymmetric Encryption | 4096-bit |  | Key wrapping, zero-knowledge |
| **PBKDF2** | Key Derivation | Variable |  | Password-to-key derivation |
| **SHA-256** | Hash Function | - |  | Authentication, integrity |

---

## Symmetric Encryption Algorithms

### 1. AES-256-GCM (Recommended) 

**Full Name:** Advanced Encryption Standard with 256-bit key in Galois/Counter Mode

**Specifications:**
- **Block Size:** 128 bits
- **Key Size:** 256 bits (32 bytes)
- **IV/Nonce Size:** 96 bits (12 bytes) — *recommended*
- **Authentication Tag Size:** 128 bits (16 bytes)
- **Algorithm Complexity:** O(n) where n = plaintext length

**Security Properties:**
-  **Confidentiality:** NIST-approved, military-grade encryption
-  **Authenticity:** Built-in authentication (GCM mode)
-  **Integrity:** Detects any tampering with ciphertext
-  **No padding needed:** Counter mode doesn't require padding
-  **Parallelizable:** Fast on modern hardware

**Why GCM Mode?**
- **Authenticated Encryption with Associated Data (AEAD):** Combines encryption and authentication in a single operation
- **Prevents tampering:** If someone modifies the encrypted data, decryption will fail
- **Industry standard:** Used by TLS 1.2/1.3, IPsec, SSH, Google, AWS, etc.

**Use Cases:**
-  File encryption (all file types and sizes)
-  Form data encryption
-  Message encryption
-  Default choice for new applications

**Implementation Details:**
```typescript
// Encryption
const iv = crypto.getRandomValues(new Uint8Array(12));
const ciphertext = await crypto.subtle.encrypt(
  { name: 'AES-GCM', iv },
  key,
  data
);

// Decryption (will throw if authentication fails)
const plaintext = await crypto.subtle.decrypt(
  { name: 'AES-GCM', iv },
  key,
  ciphertext
);
```

**Security Considerations:**
-  **NEVER reuse the same (key, IV) pair** — Each encryption must use a unique IV
-  **IV must be random** — Use `crypto.getRandomValues()`, not sequential counters
-  **IV does NOT need to be secret** — But must be random and unique
-  **Recommended:** Use 96-bit (12-byte) IVs for best performance

**Threat Model:**
-  Protects against: CPA (Chosen Plaintext Attack), MITM, tampering
-  Does NOT protect against: Traffic analysis (ciphertext size visible)

---

### 2. AES-256-CBC (Legacy)

**Full Name:** Advanced Encryption Standard with 256-bit key in Cipher Block Chaining mode

**Specifications:**
- **Block Size:** 128 bits
- **Key Size:** 256 bits
- **IV Size:** 128 bits (16 bytes) — required and unique
- **Authentication:**  NONE — requires separate authentication mechanism
- **Padding:** PKCS#7 required (16 bytes overhead max)

**Why NOT Recommended:**
-  No built-in authentication (unauthenticated encryption)
-  Vulnerable to padding oracle attacks if not used carefully
-  Slower than GCM (sequential block processing)
-  Malleability: Attacker can modify ciphertext to modify plaintext

**Use Cases:**
-  Legacy systems that can't upgrade to GCM
-  Interoperability with older encryption libraries

**Do NOT use for new projects** — Use AES-256-GCM instead.

---

### 3. AES-256-CTR (Stream Cipher)

**Full Name:** Advanced Encryption Standard with 256-bit key in Counter mode

**Specifications:**
- **Block Size:** 128 bits
- **Key Size:** 256 bits
- **Counter/IV Size:** 128 bits (16 bytes)
- **Authentication:**  NONE — unauthenticated
- **Padding:**  NONE needed — true stream cipher

**When to Use:**
-  Large files (no padding overhead)
-  Streaming encryption
-  When you need deterministic output length
-  Requires separate authentication (e.g., HMAC-SHA256)

**Security Considerations:**
-  Same (key, counter) reuse = complete plaintext recovery
-  Counter must be unique across all encryptions with the same key
-  **No built-in authentication** — prone to tampering

**Comparison: AES-CTR vs AES-GCM**

| Aspect | AES-CTR | AES-GCM |
|--------|---------|---------|
| Authentication |  No |  Yes |
| Padding overhead | 0 bytes | 16 bytes |
| Tamper detection |  No |  Yes |
| Speed | Fast | Fast |
| **Recommendation** | Use with caution |  **Recommended** |

---

## Asymmetric Encryption (Key Management)

### RSA-OAEP (4096-bit)

**Full Name:** RSA Optimal Asymmetric Encryption Padding

**Specifications:**
- **Key Size:** 4096 bits (512 bytes)
- **Security Level:** ~128-bit equivalent (post-NIST recommendations)
- **Hash Function:** SHA-256
- **Typical Use:** Key wrapping, not file encryption

**Use Cases:**
-  Zero-knowledge encryption mode (wrapping CEK with public key)
-  Key distribution
-  One-time key establishment

**Why 4096-bit?**
- 2048-bit RSA: ~112-bit security (deprecated after 2030)
- 4096-bit RSA: ~128-bit security (recommended until 2050+)

**Important Limitations:**
-  **SLOW** — Cannot encrypt large files directly
-  **Typical use:** Encrypt small keys (32-64 bytes), not files
-  **Hybrid approach:** Use RSA to encrypt AES key, then AES to encrypt file

**Security Considerations:**
-  Requires secure random padding (built-in with OAEP)
-  Private key must never leave the client (in zero-knowledge mode)
-  Vulnerable to side-channel attacks if used improperly

---

## Post-Quantum Cryptography

### ML-KEM (Kyber) — Post-Quantum Key Encapsulation

**Full Name:** Module-Lattice-Based Key-Encapsulation Mechanism (NIST FIPS 203)

**Why Post-Quantum?**
- RSA/ECC vulnerable to quantum computers (Shor's algorithm)
- Lattice-based crypto is quantum-resistant
- NIST standardized ML-KEM in August 2024

**Two Variants:**

#### ML-KEM-768 (Recommended)
- **Security Level:** ~192-bit (post-quantum) / ~AES-192 (classical)
- **Ciphertext Size:** 1088 bytes
- **Shared Secret Size:** 32 bytes
- **Use:** Most applications, good balance

#### ML-KEM-1024
- **Security Level:** ~256-bit (post-quantum) / ~AES-256 (classical)
- **Ciphertext Size:** 1568 bytes
- **Shared Secret Size:** 32 bytes
- **Use:** High-security applications, compliance requirements

**How It Works (Hybrid Encryption):**

```
1. Encapsulation (Sender)
   ├─ Generate KEM keypair from password seed
   ├─ Encapsulate: generate shared secret + KEM ciphertext
   ├─ Use shared secret as AES-256-GCM key
   └─ Encrypt file with AES-GCM
   └─ Transmit: [KEM ciphertext] + [AES-encrypted file]

2. Decapsulation (Receiver)
   ├─ Regenerate same KEM keypair from password + salt
   ├─ Decapsulate: recover shared secret from KEM ciphertext
   ├─ Use same shared secret as AES key
   └─ Decrypt file with AES-GCM
```

**Security Properties:**
-  **CPA-secure:** Protects against chosen plaintext attacks
-  **Quantum-resistant:** Secure against quantum computers
-  **Deterministic derivation:** Same password + salt = same keypair
-  **No key storage:** Key derived on-the-fly from password

**Use Cases:**
-  Future-proofing against quantum threats
-  Compliance with quantum-readiness requirements
-  Long-term archival of sensitive data
-  Government/enterprise encryption standards

**Ciphertext Size Overhead:**

| Algorithm | Overhead | Example: 10MB file |
|-----------|----------|-------------------|
| AES-256-GCM | 16 bytes | 10.00 MB |
| Kyber-768-AES | 1088 bytes | 10.00 MB |
| Kyber-1024-AES | 1568 bytes | 10.00 MB |

---

## Key Derivation: PBKDF2

**Full Name:** Password-Based Key Derivation Function 2 (NIST SP 800-132)

**Specifications:**
- **Hash Function:** SHA-256
- **Iterations:** 600,000 (industry standard for 2024)
- **Salt Size:** 32 bytes (256 bits)
- **Derived Key Length:** Variable (typically 32 bytes for AES-256)

**How It Works:**
```
PBKDF2(password, salt, iterations, keyLength)
│
├─ 1. Import password as key material
├─ 2. Repeat 600K times: HMAC-SHA256(key_material, salt)
├─ 3. Output: 32-byte derived key
└─ Result: Key suitable for AES encryption
```

**Why 600,000 Iterations?**
- **2024 Standard:** NIST recommends 600,000+ for SHA-256
- **Security Trade-off:** Slower = more expensive for attackers to brute-force
- **Computational Cost:** ~1-2 seconds on modern hardware per key derivation
- **History:**
  - 2010: 1,000 iterations
  - 2015: 100,000 iterations (OWASP)
  - 2024: 600,000+ iterations

**Iteration Cost Comparison:**

| Iterations | Time (Modern CPU) | Brute-force Cost |
|-----------|------------------|-----------------|
| 1,000 | 2ms |  Cheap |
| 100,000 | 200ms |  Moderate |
| 600,000 | 1.2s |  Expensive |
| 1,000,000 | 2s |  Very Expensive |

**Salt Management:**
-  **Must be random:** Use `crypto.getRandomValues()`
-  **Must be unique:** Each password gets a unique salt
-  **Salt can be public:** Transmitted with encrypted data
-  **Never reuse salt:** Different passwords need different salts

**Password Requirements (Enforced):**
- Minimum 8 characters
- At least 1 uppercase letter
- At least 1 lowercase letter
- At least 1 number
- At least 1 special character
- Recommended: 12+ characters

---

## Hash Function: SHA-256

**Full Name:** Secure Hash Algorithm 256-bit (NIST FIPS 180-4)

**Specifications:**
- **Output Size:** 256 bits (32 bytes)
- **Hash Family:** SHA-2 (successor to SHA-1)
- **Security Level:** 128-bit (collision-resistant)
- **Use Cases:** Checksums, integrity verification, signatures

**Security Properties:**
-  **Collision-resistant:** Cannot find two inputs with same hash
-  **Preimage-resistant:** Cannot reverse hash to input
-  **One-way function:** Deterministic but irreversible

**Common Uses in @bunkor/crypto:**
1. **File integrity:** SHA-256(file) = checksum
2. **Key derivation:** PBKDF2 uses HMAC-SHA256 internally
3. **RSA signatures:** RSA-OAEP uses SHA-256 hashing

---

## Authentication & Integrity

### HMAC-SHA256 (Implicit)

Used internally by PBKDF2 and part of the GCM authentication.

**Properties:**
-  Detects tampering with message
-  Requires shared secret (key)
-  Used for: message authentication codes, signatures

---

## Security Recommendations

###  DO

| Recommendation | Reason |
|----------------|--------|
| Use **AES-256-GCM** for all new applications | Authenticated encryption, NIST-approved |
| Generate **random IVs** for each encryption | Prevents patterns and attacks |
| Use **600K+ PBKDF2 iterations** | Industry-standard password protection |
| Use **32-byte random salts** | Maximum entropy for password derivation |
| Use **4096-bit RSA keys** | Quantum-resistant timeline |
| Consider **ML-KEM-768** for future-proofing | Post-quantum secure |
| **Rotate keys periodically** | Defense-in-depth strategy |
| **Audit encryption usage** | Track who accessed what, when |

###  DON'T

| Anti-Pattern | Risk |
|--------------|------|
| Reuse (key, IV) pairs | Complete plaintext recovery |
| Use ECB mode | Reveals patterns in plaintext |
| Use CBC without authentication | Vulnerable to tampering (padding oracle) |
| Hardcode encryption keys | Exposed in source code, git history |
| Use weak passwords (<8 chars) | Fast brute-force attacks |
| Use <100K PBKDF2 iterations | Weak against password cracking |
| Store plaintext encryption keys | Complete compromise if breached |
| Trust unauthenticated encryption | Attacker can modify data undetected |

---

## Performance Characteristics

### Encryption Speed (Approximate)

On modern hardware (2024):

| Algorithm | Speed | Notes |
|-----------|-------|-------|
| **AES-256-GCM** | ~500-1000 MB/s | Recommended |
| AES-256-CBC | ~500-1000 MB/s | Similar to GCM |
| AES-256-CTR | ~500-1000 MB/s | No authentication overhead |
| Kyber-768-AES | ~100-200 MB/s (file) | Slow KEM, fast AES |
| RSA-4096-OAEP | ~1ms per operation | Only for key wrapping |
| PBKDF2 (600K) | ~1-2s per key derivation | Intentionally slow |

### Memory Usage

| Operation | Memory |
|-----------|--------|
| AES key (32 bytes) | 32 bytes |
| Salt (32 bytes) | 32 bytes |
| IV/Nonce (12-16 bytes) | 12-16 bytes |
| Kyber-768 keypair | ~3KB total |

---

## Browser Compatibility

All algorithms are supported in:
-  Chrome/Edge 37+
-  Firefox 34+
-  Safari 11+
-  Node.js 15+ (with `crypto.subtle`)

---

## Compliance & Standards

| Standard | Compliance | Notes |
|----------|-----------|-------|
| **NIST FIPS** |  | All algorithms NIST-approved |
| **FIPS 140-2** |  | Cryptographic module standards |
| **NIST SP 800-132** |  | PBKDF2 recommendations |
| **OWASP** |  | Exceeds OWASP password hashing standards |
| **PCI DSS** |  | Suitable for payment data protection |
| **HIPAA** |  | Strong encryption for healthcare data |
| **GDPR** |  | Encryption as security measure |
| **Post-Quantum Readiness** |  | ML-KEM support for future threats |

---

## Summary Table

| Algorithm | Recommendation | Security | Speed | Use Case |
|-----------|-----------------|----------|-------|----------|
| **AES-256-GCM** |  **Use Always** |  | Fast | All encryption |
| AES-256-CBC |  Legacy only |  | Fast | Old systems |
| AES-256-CTR |  Use with care |  | Fast | Large files |
| ML-KEM-768 |  Future-proof |  | Medium | Post-quantum |
| ML-KEM-1024 |  High-security |  | Medium | Compliance |
| RSA-4096-OAEP |  Key wrapping |  | Slow | Key exchange |
| PBKDF2 (600K) |  Always |  | Slow | Passwords → keys |
| SHA-256 |  Always |  | Fast | Hashing, checksums |

---

## References

- [NIST FIPS 197: AES](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf)
- [NIST SP 800-38D: GCM Mode](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)
- [NIST SP 800-132: PBKDF2](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf)
- [NIST FIPS 203: ML-KEM (Kyber)](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [RFC 3394: AES Key Wrap Algorithm](https://tools.ietf.org/html/rfc3394)
