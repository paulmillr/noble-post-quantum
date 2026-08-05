import {
  ml_kem512 as ts_ml_kem512,
  ml_kem768 as ts_ml_kem768,
  ml_kem1024 as ts_ml_kem1024,
} from './ml-kem.ts';
import {
  ml_dsa44 as ts_ml_dsa44,
  ml_dsa65 as ts_ml_dsa65,
  ml_dsa87 as ts_ml_dsa87,
} from './ml-dsa.ts';
import { ml_kem768_x25519 as ts_ml_kem768_x25519 } from './hybrid.ts';

import {
  ml_kem512 as wc_ml_kem512,
  ml_kem768 as wc_ml_kem768,
  ml_kem1024 as wc_ml_kem1024,
  ml_dsa44 as wc_ml_dsa44,
  ml_dsa65 as wc_ml_dsa65,
  ml_dsa87 as wc_ml_dsa87,
  ml_kem768_x25519 as wc_ml_kem768_x25519,
  type AsyncKEM,
  type AsyncDSA,
} from './webcrypto.ts';

import { type KEM, type TArg, type TRet, type SigOpts, type VerOpts } from './utils.ts';
import { type DSA } from './ml-dsa.ts';

// Chrome Canary's WebCrypto PQC implementations currently export compressed seeds wrapped in PKCS8.
// We use these exact lengths to route operations (like decapsulate/sign) to the WebCrypto backend
// when it's natively supported and the user passes a WebCrypto-generated key.
// Note: If standard implementations change their PKCS8 export format to use fully expanded keys,
// these constants will need to be updated.
const WEBCRYPTO_MLKEM_PKCS8_LENGTH = 86;
const WEBCRYPTO_MLDSA_PKCS8_LENGTH = 54;

let isMLKEM512Supported = false;
let isMLKEM768Supported = false;
let isMLKEM1024Supported = false;

let isMLDSA44Supported = false;
let isMLDSA65Supported = false;
let isMLDSA87Supported = false;

let isXWingSupported = false;

// Probe for WebCrypto support of ML-KEM, ML-DSA, and XWing algorithms.
if (typeof globalThis !== 'undefined' && globalThis.crypto && globalThis.crypto.subtle) {
  const subtle = globalThis.crypto.subtle;

  // Probe ML-KEM (subtle is cast to 'any' because standard TS types lack encapsulateBits)
  if ((subtle as any).encapsulateBits !== undefined) {
    const mlKem512Alg = { name: 'ML-KEM-512' } as any;
    const mlKem768Alg = { name: 'ML-KEM-768' } as any;
    const mlKem1024Alg = { name: 'ML-KEM-1024' } as any;
    const extractable = true;
    const keyUsages = ['encapsulateBits', 'decapsulateBits'] as any;

    subtle.generateKey(mlKem512Alg, extractable, keyUsages).then(
      () => {
        isMLKEM512Supported = true;
      },
      () => {}
    );
    subtle.generateKey(mlKem768Alg, extractable, keyUsages).then(
      () => {
        isMLKEM768Supported = true;
      },
      () => {}
    );
    subtle.generateKey(mlKem1024Alg, extractable, keyUsages).then(
      () => {
        isMLKEM1024Supported = true;
      },
      () => {}
    );
  }

  // Probe ML-DSA
  if (subtle.sign !== undefined) {
    const mlDsa44Alg = { name: 'ML-DSA-44' } as any;
    const mlDsa65Alg = { name: 'ML-DSA-65' } as any;
    const mlDsa87Alg = { name: 'ML-DSA-87' } as any;
    const extractable = true;
    const keyUsages = ['sign', 'verify'] as any;

    subtle.generateKey(mlDsa44Alg, extractable, keyUsages).then(
      () => {
        isMLDSA44Supported = true;
      },
      () => {}
    );
    subtle.generateKey(mlDsa65Alg, extractable, keyUsages).then(
      () => {
        isMLDSA65Supported = true;
      },
      () => {}
    );
    subtle.generateKey(mlDsa87Alg, extractable, keyUsages).then(
      () => {
        isMLDSA87Supported = true;
      },
      () => {}
    );
  }

  // Probe XWing
  if ((subtle as any).encapsulateBits !== undefined) {
    const xWingAlg = { name: 'MLKEM768-X25519' } as any;
    const extractable = true;
    const keyUsages = ['encapsulateBits', 'decapsulateBits'] as any;

    subtle.generateKey(xWingAlg, extractable, keyUsages).then(
      () => {
        isXWingSupported = true;
      },
      () => {}
    );
  }
}

/**
 * Creates a KEM instance that opportunistically uses the WebCrypto backend if supported,
 * but falls back to the pure TypeScript backend if native execution throws or is unsupported.
 *
 * Note on Asynchrony:
 * Although the return type is typed as `TRet` (which allows synchronous values due to upstream
 * constraints), this wrapper guarantees a fully asynchronous execution. It always returns a Promise,
 * avoiding the "Zalgo" anti-pattern. Callers must always `await` the results.
 *
 * WARNING: No Error Fallbacks (Silent Downgrade Prevention)
 * This wrapper deliberately DOES NOT catch and swallow WebCrypto errors to fall back to pure TS.
 * Doing so could mask underlying security issues (e.g., malformed ciphertexts or unsupported keys)
 * and enable downgrade attacks.
 */
function wrapMLKEMFallback(
  wcKem: TRet<AsyncKEM>,
  tsKem: TRet<KEM>,
  checkSupport: () => boolean
): TRet<AsyncKEM> {
  const impl: AsyncKEM = {
    info: tsKem.info,
    lengths: tsKem.lengths,
    async keygen(seed?: TArg<Uint8Array>, opts?: TArg<{ extractable?: boolean }>) {
      if (checkSupport() && seed === undefined) {
        return wcKem.keygen(seed, opts);
      }
      return Promise.resolve(tsKem.keygen(seed));
    },
    async getPublicKey(secretKey: TArg<Uint8Array | CryptoKey>) {
      if (
        checkSupport() &&
        (!(secretKey instanceof Uint8Array) || secretKey.length === WEBCRYPTO_MLKEM_PKCS8_LENGTH)
      ) {
        return wcKem.getPublicKey(secretKey);
      }
      return Promise.resolve(tsKem.getPublicKey(secretKey as Uint8Array));
    },
    async encapsulate(publicKey: TArg<Uint8Array>, msg?: TArg<Uint8Array>) {
      if (checkSupport() && msg === undefined) {
        return wcKem.encapsulate(publicKey);
      }
      return Promise.resolve(tsKem.encapsulate(publicKey, msg));
    },
    async decapsulate(cipherText: TArg<Uint8Array>, secretKey: TArg<Uint8Array | CryptoKey>) {
      if (
        checkSupport() &&
        (!(secretKey instanceof Uint8Array) || secretKey.length === WEBCRYPTO_MLKEM_PKCS8_LENGTH)
      ) {
        return wcKem.decapsulate(cipherText, secretKey);
      }
      return Promise.resolve(tsKem.decapsulate(cipherText, secretKey as Uint8Array));
    },
  };
  return Object.freeze(impl) as unknown as TRet<AsyncKEM>;
}

/**
 * Creates a DSA instance that opportunistically uses the WebCrypto backend if supported,
 * but falls back to the pure TypeScript backend.
 *
 * Note on Asynchrony:
 * Although the return type is typed as `TRet` (which allows synchronous values due to upstream
 * constraints), this wrapper guarantees a fully asynchronous execution. It always returns a Promise,
 * avoiding the "Zalgo" anti-pattern. Callers must always `await` the results.
 *
 * WARNING: No Error Fallbacks (Silent Downgrade Prevention)
 * This wrapper deliberately DOES NOT catch and swallow WebCrypto errors to fall back to pure TS.
 * Falling back on error could mask critical cryptographic verification failures or unsupported state
 * and enable downgrade attacks.
 */
function wrapDSAFallback(
  wcDsa: TRet<AsyncDSA>,
  tsDsa: TRet<DSA>,
  checkSupport: () => boolean
): TRet<AsyncDSA> {
  const dsaAny = tsDsa as any;
  const impl: AsyncDSA = {
    info: tsDsa.info,
    securityLevel: dsaAny.securityLevel,
    lengths: tsDsa.lengths,
    async keygen(seed?: TArg<Uint8Array>, opts?: TArg<{ extractable?: boolean }>) {
      if (checkSupport() && seed === undefined) {
        return wcDsa.keygen(seed, opts);
      }
      return Promise.resolve(tsDsa.keygen(seed));
    },
    async getPublicKey(secretKey: TArg<Uint8Array | CryptoKey>) {
      if (
        checkSupport() &&
        (!(secretKey instanceof Uint8Array) || secretKey.length === WEBCRYPTO_MLDSA_PKCS8_LENGTH)
      ) {
        return wcDsa.getPublicKey(secretKey);
      }
      return Promise.resolve(tsDsa.getPublicKey(secretKey as Uint8Array));
    },
    async sign(
      msg: TArg<Uint8Array>,
      secretKey: TArg<Uint8Array | CryptoKey>,
      opts: TArg<SigOpts> = {}
    ) {
      if (
        checkSupport() &&
        (!(secretKey instanceof Uint8Array) || secretKey.length === WEBCRYPTO_MLDSA_PKCS8_LENGTH)
      ) {
        return wcDsa.sign(msg, secretKey, opts);
      }
      return Promise.resolve(tsDsa.sign(msg, secretKey as Uint8Array, opts));
    },
    async verify(
      sig: TArg<Uint8Array>,
      msg: TArg<Uint8Array>,
      publicKey: TArg<Uint8Array>,
      opts: TArg<VerOpts> = {}
    ) {
      if (checkSupport()) {
        return wcDsa.verify(sig, msg, publicKey, opts);
      }
      return Promise.resolve(tsDsa.verify(sig, msg, publicKey, opts));
    },
    prehash: dsaAny.prehash,
    internal: dsaAny.internal,
  };
  return Object.freeze(impl) as unknown as TRet<AsyncDSA>;
}

export const ml_kem512: TRet<AsyncKEM> = /* @__PURE__ */ wrapMLKEMFallback(
  wc_ml_kem512,
  ts_ml_kem512,
  () => isMLKEM512Supported
);
export const ml_kem768: TRet<AsyncKEM> = /* @__PURE__ */ wrapMLKEMFallback(
  wc_ml_kem768,
  ts_ml_kem768,
  () => isMLKEM768Supported
);
export const ml_kem1024: TRet<AsyncKEM> = /* @__PURE__ */ wrapMLKEMFallback(
  wc_ml_kem1024,
  ts_ml_kem1024,
  () => isMLKEM1024Supported
);

export const ml_dsa44: TRet<AsyncDSA> = /* @__PURE__ */ wrapDSAFallback(
  wc_ml_dsa44,
  ts_ml_dsa44,
  () => isMLDSA44Supported
);
export const ml_dsa65: TRet<AsyncDSA> = /* @__PURE__ */ wrapDSAFallback(
  wc_ml_dsa65,
  ts_ml_dsa65,
  () => isMLDSA65Supported
);
export const ml_dsa87: TRet<AsyncDSA> = /* @__PURE__ */ wrapDSAFallback(
  wc_ml_dsa87,
  ts_ml_dsa87,
  () => isMLDSA87Supported
);

/**
 * Hybrid fallback implementation of X-Wing (MLKEM768-X25519).
 *
 * Note on Asynchrony:
 * Although the return type is typed as `TRet` (which allows synchronous values),
 * this wrapper guarantees a fully asynchronous execution. It always returns a Promise,
 * avoiding the "Zalgo" anti-pattern. Callers must always `await` the results.
 */
const xWingImpl: AsyncKEM = {
  info: ts_ml_kem768_x25519.info,
  lengths: {
    ...ts_ml_kem768_x25519.lengths,
    secretKey: 1248, // Support both sizes in fallback (input can be 32 or 1248)
  },
  async keygen(seed?: TArg<Uint8Array>, opts?: TArg<{ extractable?: boolean }>) {
    if (isXWingSupported && seed === undefined) {
      return wc_ml_kem768_x25519.keygen(seed, opts);
    }
    return Promise.resolve(ts_ml_kem768_x25519.keygen(seed));
  },
  async getPublicKey(secretKey: TArg<Uint8Array | CryptoKey>) {
    if (!(secretKey instanceof Uint8Array)) {
      return wc_ml_kem768_x25519.getPublicKey(secretKey);
    }
    const skBytes = secretKey;
    if (skBytes.length === 1248) {
      return wc_ml_kem768_x25519.getPublicKey(secretKey);
    }
    return Promise.resolve(ts_ml_kem768_x25519.getPublicKey(secretKey));
  },
  async encapsulate(publicKey: TArg<Uint8Array>, msg?: TArg<Uint8Array>) {
    if (isXWingSupported && msg === undefined) {
      return wc_ml_kem768_x25519.encapsulate(publicKey);
    }
    return Promise.resolve(ts_ml_kem768_x25519.encapsulate(publicKey, msg));
  },
  async decapsulate(cipherText: TArg<Uint8Array>, secretKey: TArg<Uint8Array | CryptoKey>) {
    if (isXWingSupported) {
      return wc_ml_kem768_x25519.decapsulate(cipherText, secretKey);
    }
    return Promise.resolve(ts_ml_kem768_x25519.decapsulate(cipherText, secretKey as Uint8Array));
  },
};
export const ml_kem768_x25519: TRet<AsyncKEM> = Object.freeze(
  xWingImpl
) as unknown as TRet<AsyncKEM>;

export const XWing: TRet<AsyncKEM> = ml_kem768_x25519;
export const MLKEM768X25519: TRet<AsyncKEM> = ml_kem768_x25519;
