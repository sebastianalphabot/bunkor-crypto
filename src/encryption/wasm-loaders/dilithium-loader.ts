/**
 * Dynamic loader for Dilithium (ML-DSA) cryptography
 *
 * NOTE: pqc-dilithium uses WASM which is not compatible with Angular's Zone.js
 * Until a pure JavaScript implementation is available, this algorithm is disabled.
 *
 * Alternatives being evaluated:
 * - @noble/post-quantum (when released)
 * - ml-dsa-js (if available)
 */

export async function loadDilithium(): Promise<never> {
  throw new Error(
    'Dilithium-Signature is temporarily unavailable. ' +
    'The pqc-dilithium library uses WASM which is not compatible with Angular Zone.js. ' +
    'Please use a different encryption algorithm such as AES-256-GCM or Kyber-KEM.'
  );
}
