/**
 * Dynamic loader for ML-KEM (Kyber) cryptography
 * Uses mlkem package which is a pure TypeScript implementation (no WASM)
 * This avoids Angular Zone.js WASM compatibility issues
 */

let kyberModule: any = null;

export async function loadKyber() {
  if (kyberModule) {
    return kyberModule;
  }

  try {
    // Dynamic import of mlkem (pure TypeScript implementation)
    // This replaces pqc-kyber which uses WASM and has Zone.js issues
    const mlkem = await import('mlkem');

    // Create a wrapper that matches the pqc-kyber API
    // Note: mlkem methods are async, so all wrapper methods must be async
    kyberModule = {
      /**
       * Generate a new Kyber-768 keypair
       * @returns {Promise<{ pubkey: Uint8Array, secret: Uint8Array }>}
       */
      keypair: async () => {
        const kem = new mlkem.MlKem768();
        const [publicKey, secretKey] = await kem.generateKeyPair();
        return {
          pubkey: publicKey,
          secret: secretKey
        };
      },

      /**
       * Encapsulate: Generate shared secret using public key
       * @param pubkey - Public key
       * @returns {Promise<{ ciphertext: Uint8Array, sharedSecret: Uint8Array }>}
       */
      encapsulate: async (pubkey: Uint8Array) => {
        const kem = new mlkem.MlKem768();
        const [ciphertext, sharedSecret] = await kem.encap(pubkey);
        return {
          ciphertext,
          sharedSecret
        };
      },

      /**
       * Decapsulate: Recover shared secret using secret key
       * @param ciphertext - The encapsulated ciphertext
       * @param secret - Secret key
       * @returns {Promise<Uint8Array>} The shared secret
       */
      decapsulate: async (ciphertext: Uint8Array, secret: Uint8Array) => {
        const kem = new mlkem.MlKem768();
        return await kem.decap(ciphertext, secret);
      }
    };

    return kyberModule;
  } catch (error) {
    console.error('Failed to load mlkem:', error);
    throw new Error('Failed to load Kyber library. Please try again or use a different encryption algorithm.');
  }
}
