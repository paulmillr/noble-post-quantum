import { type TArg, type TRet, type SigOpts, type VerOpts, unwrapSPKI, wrapSPKI } from './utils.ts';

export type PQCKeyUsage = KeyUsage | 'encapsulateBits' | 'decapsulateBits';

export type PQCSubtleCrypto = Omit<
  SubtleCrypto,
  'generateKey' | 'importKey' | 'sign' | 'verify'
> & {
  generateKey(
    algorithm: AlgorithmIdentifier | { name: string },
    extractable: boolean,
    keyUsages: readonly PQCKeyUsage[]
  ): Promise<CryptoKeyPair>;
  importKey(
    format: 'jwk',
    keyData: JsonWebKey,
    algorithm: AlgorithmIdentifier | { name: string },
    extractable: boolean,
    keyUsages: readonly PQCKeyUsage[]
  ): Promise<CryptoKey>;
  importKey(
    format: Exclude<KeyFormat, 'jwk'> | 'raw-seed',
    keyData: BufferSource | Uint8Array,
    algorithm: AlgorithmIdentifier | { name: string },
    extractable: boolean,
    keyUsages: readonly PQCKeyUsage[]
  ): Promise<CryptoKey>;
  getPublicKey(key: CryptoKey, keyUsages: readonly PQCKeyUsage[]): Promise<CryptoKey>;
  encapsulateBits(
    algorithm: AlgorithmIdentifier | { name: string },
    key: CryptoKey
  ): Promise<{ sharedKey: ArrayBuffer; ciphertext: ArrayBuffer }>;
  decapsulateBits(
    algorithm: AlgorithmIdentifier | { name: string },
    key: CryptoKey,
    ciphertext: BufferSource | Uint8Array
  ): Promise<ArrayBuffer>;
  sign(
    algorithm: AlgorithmIdentifier | { name: string },
    key: CryptoKey,
    data: BufferSource | Uint8Array
  ): Promise<ArrayBuffer>;
  verify(
    algorithm: AlgorithmIdentifier | { name: string },
    key: CryptoKey,
    signature: BufferSource | Uint8Array,
    data: BufferSource | Uint8Array
  ): Promise<boolean>;
};

export type AsyncKEM = {
  info?: { type?: string };
  lengths: {
    seed?: number;
    publicKey?: number;
    secretKey?: number;
    cipherText?: number;
    msg?: number;
    msgRand?: number;
  };
  keygen: (
    seed?: TArg<Uint8Array>,
    opts?: TArg<{ extractable?: boolean }>
  ) => Promise<{ secretKey: TRet<Uint8Array | CryptoKey>; publicKey: TRet<Uint8Array> }>;
  getPublicKey: (secretKey: TArg<Uint8Array | CryptoKey>) => Promise<TRet<Uint8Array>>;
  encapsulate: (
    publicKey: TArg<Uint8Array>,
    msg?: TArg<Uint8Array>
  ) => Promise<{ cipherText: TRet<Uint8Array>; sharedSecret: TRet<Uint8Array> }>;
  decapsulate: (
    cipherText: TArg<Uint8Array>,
    secretKey: TArg<Uint8Array | CryptoKey>
  ) => Promise<TRet<Uint8Array>>;
};

export type AsyncDSA = {
  info?: { type?: string };
  securityLevel: number;
  lengths: {
    seed?: number;
    publicKey?: number;
    secretKey?: number;
    signRand?: number;
    signature?: number;
  };
  keygen: (
    seed?: TArg<Uint8Array>,
    opts?: TArg<{ extractable?: boolean }>
  ) => Promise<{ secretKey: TRet<Uint8Array | CryptoKey>; publicKey: TRet<Uint8Array> }>;
  getPublicKey: (secretKey: TArg<Uint8Array | CryptoKey>) => Promise<TRet<Uint8Array>>;
  sign: (
    msg: TArg<Uint8Array>,
    secretKey: TArg<Uint8Array | CryptoKey>,
    opts?: TArg<SigOpts>
  ) => Promise<TRet<Uint8Array>>;
  verify: (
    sig: TArg<Uint8Array>,
    msg: TArg<Uint8Array>,
    publicKey: TArg<Uint8Array>,
    opts?: TArg<VerOpts>
  ) => Promise<boolean>;
  prehash: () => void;
  internal?: any;
};

export function base64url(bytes: Uint8Array): string {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function debase64url(str: string): Uint8Array {
  let s = str;
  const pad = s.length % 4;
  if (pad === 2) s += '==';
  else if (pad === 3) s += '=';
  const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/'));
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

export const ML_KEM_OIDS: Record<number, Uint8Array> = {
  // ML-KEM-512 OID: 2.16.840.1.101.3.4.4.1
  2: new Uint8Array([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x01]),
  // ML-KEM-768 OID: 2.16.840.1.101.3.4.4.2
  3: new Uint8Array([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x02]),
  // ML-KEM-1024 OID: 2.16.840.1.101.3.4.4.3
  4: new Uint8Array([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x03]),
};

export const ML_DSA_OIDS: Record<number, Uint8Array> = {
  // ML-DSA-44 OID: 2.16.840.1.101.3.4.3.17
  4: new Uint8Array([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11]),
  // ML-DSA-65 OID: 2.16.840.1.101.3.4.3.18
  6: new Uint8Array([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12]),
  // ML-DSA-87 OID: 2.16.840.1.101.3.4.3.19
  8: new Uint8Array([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13]),
};

const isWebCryptoSupported =
  typeof globalThis !== 'undefined' && globalThis.crypto && globalThis.crypto.subtle !== undefined;

function getSubtle(): PQCSubtleCrypto {
  return globalThis.crypto.subtle as unknown as PQCSubtleCrypto;
}

function assertSupported() {
  if (!isWebCryptoSupported) {
    throw new DOMException('WebCrypto is not supported in this environment', 'NotSupportedError');
  }
}

/**
 * Wraps WebCrypto ML-KEM APIs into a unified interface matching the pure TypeScript implementation.
 *
 * This implementation uses a custom PQCSubtleCrypto interface to ensure strong typing.
 */
function wrapMLKEM(K: number, algName: string, lengths: AsyncKEM['lengths']): TRet<AsyncKEM> {
  const impl: AsyncKEM = {
    info: Object.freeze({ type: 'ml-kem' }),
    lengths,
    async keygen(seed?: TArg<Uint8Array>, opts?: TArg<{ extractable?: boolean }>) {
      assertSupported();
      if (seed !== undefined) {
        throw new Error('Deterministic keygen with seed is not supported in pure WebCrypto');
      }
      const algorithm = { name: algName };
      const extractable = opts?.extractable ?? false;
      const keyUsages: readonly PQCKeyUsage[] = ['encapsulateBits', 'decapsulateBits'];
      const keyPair = await getSubtle().generateKey(algorithm, extractable, keyUsages);

      const formatSpki = 'spki';
      const publicKeyBuffer = await getSubtle().exportKey(formatSpki, keyPair.publicKey);

      let secretKey: TRet<Uint8Array | CryptoKey> =
        keyPair.privateKey as unknown as TRet<CryptoKey>;
      if (extractable) {
        const formatPkcs8 = 'pkcs8';
        const secretKeyBuffer = await getSubtle().exportKey(formatPkcs8, keyPair.privateKey);
        secretKey = new Uint8Array(secretKeyBuffer as ArrayBuffer) as TRet<Uint8Array>;
      }

      return {
        publicKey: unwrapSPKI(new Uint8Array(publicKeyBuffer as ArrayBuffer)) as TRet<Uint8Array>,
        secretKey,
      };
    },
    async getPublicKey(secretKey: TArg<Uint8Array | CryptoKey>) {
      assertSupported();
      let privateKey: CryptoKey;
      if (secretKey instanceof Uint8Array) {
        const format = 'pkcs8';
        const keyData = secretKey;
        const algorithm = { name: algName };
        const extractable = false;
        const keyUsages: readonly PQCKeyUsage[] = ['decapsulateBits'];
        privateKey = await getSubtle().importKey(
          format,
          keyData,
          algorithm,
          extractable,
          keyUsages
        );
      } else {
        privateKey = secretKey as CryptoKey;
      }
      const publicKey = await getSubtle().getPublicKey(privateKey, ['encapsulateBits']);

      const formatSpki = 'spki';
      const publicKeyBuffer = await getSubtle().exportKey(formatSpki, publicKey);
      return unwrapSPKI(new Uint8Array(publicKeyBuffer as ArrayBuffer)) as TRet<Uint8Array>;
    },
    async encapsulate(publicKey: TArg<Uint8Array>, msg?: TArg<Uint8Array>) {
      assertSupported();
      if (msg !== undefined) {
        throw new Error(
          'Encapsulate with custom message/entropy is not supported in pure WebCrypto'
        );
      }
      const oid = ML_KEM_OIDS[K];
      if (!oid) throw new Error('Unsupported K size');
      const spki = wrapSPKI(oid, publicKey as Uint8Array);
      const format = 'spki';
      const keyData = spki as Uint8Array;
      const algorithm = { name: algName };
      const extractable = true;
      const keyUsages: readonly PQCKeyUsage[] = ['encapsulateBits'];
      const pubKey = await getSubtle().importKey(
        format,
        keyData,
        algorithm,
        extractable,
        keyUsages
      );
      const { sharedKey, ciphertext } = await getSubtle().encapsulateBits(
        { name: algName },
        pubKey
      );
      return {
        cipherText: new Uint8Array(ciphertext as ArrayBuffer) as TRet<Uint8Array>,
        sharedSecret: new Uint8Array(sharedKey as ArrayBuffer) as TRet<Uint8Array>,
      };
    },
    async decapsulate(cipherText: TArg<Uint8Array>, secretKey: TArg<Uint8Array | CryptoKey>) {
      assertSupported();
      let privKey: CryptoKey;
      if (secretKey instanceof Uint8Array) {
        const format = 'pkcs8';
        const keyData = secretKey;
        const algorithm = { name: algName };
        const extractable = false;
        const keyUsages: readonly PQCKeyUsage[] = ['decapsulateBits'];
        privKey = await getSubtle().importKey(format, keyData, algorithm, extractable, keyUsages);
      } else {
        privKey = secretKey as CryptoKey;
      }
      const sharedSecret = await getSubtle().decapsulateBits(
        { name: algName },
        privKey,
        cipherText as Uint8Array
      );
      return new Uint8Array(sharedSecret as ArrayBuffer) as TRet<Uint8Array>;
    },
  };
  return Object.freeze(impl) as unknown as TRet<AsyncKEM>;
}

/**
 * Wraps WebCrypto ML-DSA APIs into a unified interface matching the pure TypeScript implementation.
 *
 * This implementation uses a custom PQCSubtleCrypto interface to ensure strong typing.
 */
function wrapDSA(
  K: number,
  algName: string,
  lengths: AsyncDSA['lengths'],
  securityLevel: number
): TRet<AsyncDSA> {
  const impl: AsyncDSA = {
    info: Object.freeze({ type: 'ml-dsa' }),
    securityLevel,
    lengths,
    async keygen(seed?: TArg<Uint8Array>, opts?: TArg<{ extractable?: boolean }>) {
      assertSupported();
      if (seed !== undefined) {
        throw new Error('Deterministic keygen with seed is not supported in pure WebCrypto');
      }
      const algorithm = { name: algName };
      const extractable = opts?.extractable ?? false;
      const keyUsages: readonly PQCKeyUsage[] = ['sign', 'verify'];
      const keyPair = await getSubtle().generateKey(algorithm, extractable, keyUsages);

      const formatSpki = 'spki';
      const publicKeyBuffer = await getSubtle().exportKey(formatSpki, keyPair.publicKey);

      let secretKey: TRet<Uint8Array | CryptoKey> =
        keyPair.privateKey as unknown as TRet<CryptoKey>;
      if (extractable) {
        const formatPkcs8 = 'pkcs8';
        const secretKeyBuffer = await getSubtle().exportKey(formatPkcs8, keyPair.privateKey);
        secretKey = new Uint8Array(secretKeyBuffer as ArrayBuffer) as TRet<Uint8Array>;
      }

      return {
        publicKey: unwrapSPKI(new Uint8Array(publicKeyBuffer as ArrayBuffer)) as TRet<Uint8Array>,
        secretKey,
      };
    },
    async getPublicKey(secretKey: TArg<Uint8Array | CryptoKey>) {
      assertSupported();
      let privateKey: CryptoKey;
      if (secretKey instanceof Uint8Array) {
        const format = 'pkcs8';
        const keyData = secretKey;
        const algorithm = { name: algName };
        const extractable = false;
        const keyUsages: readonly PQCKeyUsage[] = ['sign'];
        privateKey = await getSubtle().importKey(
          format,
          keyData,
          algorithm,
          extractable,
          keyUsages
        );
      } else {
        privateKey = secretKey as CryptoKey;
      }
      const publicKey = await getSubtle().getPublicKey(privateKey, ['verify']);

      const formatSpki = 'spki';
      const publicKeyBuffer = await getSubtle().exportKey(formatSpki, publicKey);
      return unwrapSPKI(new Uint8Array(publicKeyBuffer as ArrayBuffer)) as TRet<Uint8Array>;
    },
    async sign(
      msg: TArg<Uint8Array>,
      secretKey: TArg<Uint8Array | CryptoKey>,
      opts: TArg<SigOpts> = {}
    ) {
      assertSupported();
      let privKey: CryptoKey;
      if (secretKey instanceof Uint8Array) {
        const format = 'pkcs8';
        const keyData = secretKey;
        const algorithm = { name: algName };
        const extractable = false;
        const keyUsages: readonly PQCKeyUsage[] = ['sign'];
        privKey = await getSubtle().importKey(format, keyData, algorithm, extractable, keyUsages);
      } else {
        privKey = secretKey as CryptoKey;
      }
      const algParams: any = { name: algName };
      if (opts.context !== undefined) {
        algParams.context = opts.context;
      }
      const signature = await getSubtle().sign(algParams, privKey, msg as Uint8Array);
      return new Uint8Array(signature as ArrayBuffer) as TRet<Uint8Array>;
    },
    async verify(
      sig: TArg<Uint8Array>,
      msg: TArg<Uint8Array>,
      publicKey: TArg<Uint8Array>,
      opts: TArg<VerOpts> = {}
    ) {
      assertSupported();
      const oid = ML_DSA_OIDS[K];
      if (!oid) throw new Error('Unsupported K size');
      const wrappedKey = wrapSPKI(oid, publicKey as Uint8Array);
      const format = 'spki';
      const keyData = wrappedKey as Uint8Array;
      const algorithm = { name: algName };
      const extractable = false;
      const keyUsages: readonly PQCKeyUsage[] = ['verify'];
      const importedKey = await getSubtle().importKey(
        format,
        keyData,
        algorithm,
        extractable,
        keyUsages
      );
      const algParams: any = { name: algName };
      if (opts.context !== undefined) {
        algParams.context = opts.context;
      }
      return await getSubtle().verify(algParams, importedKey, sig as Uint8Array, msg as Uint8Array);
    },
    prehash() {
      throw new Error('Prehash is not supported in pure WebCrypto submodule');
    },
  };
  return Object.freeze(impl) as unknown as TRet<AsyncDSA>;
}

export const ml_kem512: TRet<AsyncKEM> = /* @__PURE__ */ wrapMLKEM(2, 'ML-KEM-512', {
  seed: 64,
  msg: 32,
  msgRand: 32,
  secretKey: 86,
  publicKey: 800,
  cipherText: 768,
});
export const ml_kem768: TRet<AsyncKEM> = /* @__PURE__ */ wrapMLKEM(3, 'ML-KEM-768', {
  seed: 64,
  msg: 32,
  msgRand: 32,
  secretKey: 86,
  publicKey: 1184,
  cipherText: 1088,
});
export const ml_kem1024: TRet<AsyncKEM> = /* @__PURE__ */ wrapMLKEM(4, 'ML-KEM-1024', {
  seed: 64,
  msg: 32,
  msgRand: 32,
  secretKey: 86,
  publicKey: 1568,
  cipherText: 1568,
});

export const ml_dsa44: TRet<AsyncDSA> = /* @__PURE__ */ wrapDSA(
  4,
  'ML-DSA-44',
  { seed: 32, secretKey: 54, publicKey: 1312, signature: 2420 },
  128
);
export const ml_dsa65: TRet<AsyncDSA> = /* @__PURE__ */ wrapDSA(
  6,
  'ML-DSA-65',
  { seed: 32, secretKey: 54, publicKey: 1952, signature: 3300 },
  192
);
export const ml_dsa87: TRet<AsyncDSA> = /* @__PURE__ */ wrapDSA(
  8,
  'ML-DSA-87',
  { seed: 32, secretKey: 54, publicKey: 2592, signature: 4627 },
  256
);

const XWING_ALG_NAME = 'MLKEM768-X25519';

/**
 * Native WebCrypto implementation of X-Wing (MLKEM768-X25519).
 */
const xWingImpl: AsyncKEM = {
  info: Object.freeze({ type: 'ml-kem-x25519' }),
  lengths: {
    seed: 32,
    publicKey: 1216,
    secretKey: 1248,
    cipherText: 1120,
  },
  async keygen(seed?: TArg<Uint8Array>, opts?: TArg<{ extractable?: boolean }>) {
    assertSupported();
    if (seed !== undefined) {
      throw new Error('Deterministic keygen with seed is not supported in pure WebCrypto');
    }
    const algorithm = { name: XWING_ALG_NAME };
    const extractable = opts?.extractable ?? false;
    const keyUsages: readonly PQCKeyUsage[] = ['encapsulateBits', 'decapsulateBits'];
    const kp = await getSubtle().generateKey(algorithm, extractable, keyUsages);

    const formatJwk = 'jwk';
    const jwkPub = await getSubtle().exportKey(formatJwk, kp.publicKey);
    const pubBytes = debase64url((jwkPub as any).pub!);

    let secretKey: TRet<Uint8Array | CryptoKey> = kp.privateKey as unknown as TRet<CryptoKey>;
    if (extractable) {
      const jwkPriv = await getSubtle().exportKey(formatJwk, kp.privateKey);
      const privBytes = debase64url((jwkPriv as any).priv!);
      const secretKeyBytes = new Uint8Array(privBytes.length + pubBytes.length);
      secretKeyBytes.set(privBytes, 0);
      secretKeyBytes.set(pubBytes, privBytes.length);
      secretKey = secretKeyBytes as TRet<Uint8Array>;
    }

    return {
      publicKey: pubBytes as TRet<Uint8Array>,
      secretKey,
    };
  },
  async getPublicKey(secretKey: TArg<Uint8Array | CryptoKey>) {
    assertSupported();
    if (!(secretKey instanceof Uint8Array)) {
      const pubKey = await getSubtle().getPublicKey(secretKey as CryptoKey, ['encapsulateBits']);
      const formatJwk = 'jwk';
      const jwkPub = await getSubtle().exportKey(formatJwk, pubKey);
      return debase64url((jwkPub as any).pub!) as TRet<Uint8Array>;
    }
    const skBytes = secretKey;
    if (skBytes.length === 1248) {
      return skBytes.subarray(32) as TRet<Uint8Array>;
    }
    if (skBytes.length === 32) {
      const format = 'raw-seed';
      const algorithm = { name: XWING_ALG_NAME };
      const extractable = false;
      const keyUsages: readonly PQCKeyUsage[] = ['decapsulateBits'];
      const privKey = await getSubtle().importKey(
        format as Exclude<KeyFormat, 'jwk'> | 'raw-seed',
        skBytes,
        algorithm,
        extractable,
        keyUsages
      );
      const pubKey = await getSubtle().getPublicKey(privKey, ['encapsulateBits']);
      const formatJwk = 'jwk';
      const jwkPub = await getSubtle().exportKey(formatJwk, pubKey);
      return debase64url((jwkPub as any).pub!) as TRet<Uint8Array>;
    }
    throw new Error('Invalid secret key length');
  },
  async encapsulate(publicKey: TArg<Uint8Array>, msg?: TArg<Uint8Array>) {
    assertSupported();
    if (msg !== undefined) {
      throw new Error('Encapsulate with custom message/entropy is not supported in pure WebCrypto');
    }
    const formatJwk = 'jwk';
    const keyData = {
      kty: 'AKP',
      alg: XWING_ALG_NAME,
      key_ops: ['encapsulateBits'],
      ext: true,
      pub: base64url(publicKey as Uint8Array),
    };
    const algorithm = { name: XWING_ALG_NAME };
    const extractable = true;
    const keyUsages: readonly PQCKeyUsage[] = ['encapsulateBits'];
    const pubKey = await getSubtle().importKey(
      formatJwk,
      keyData,
      algorithm,
      extractable,
      keyUsages
    );
    const { sharedKey, ciphertext } = await getSubtle().encapsulateBits(
      { name: XWING_ALG_NAME },
      pubKey
    );
    return {
      cipherText: new Uint8Array(ciphertext as ArrayBuffer) as TRet<Uint8Array>,
      sharedSecret: new Uint8Array(sharedKey as ArrayBuffer) as TRet<Uint8Array>,
    };
  },
  async decapsulate(cipherText: TArg<Uint8Array>, secretKey: TArg<Uint8Array | CryptoKey>) {
    assertSupported();
    let privKey: CryptoKey;
    if (!(secretKey instanceof Uint8Array)) {
      privKey = secretKey as CryptoKey;
    } else {
      const skBytes = secretKey;
      if (skBytes.length === 1248) {
        const privPart = skBytes.subarray(0, 32);
        const pubPart = skBytes.subarray(32);
        const formatJwk = 'jwk';
        const keyData = {
          kty: 'AKP',
          alg: XWING_ALG_NAME,
          key_ops: ['decapsulateBits'],
          ext: true,
          priv: base64url(privPart),
          pub: base64url(pubPart),
        };
        const algorithm = { name: XWING_ALG_NAME };
        const extractable = false;
        const keyUsages: readonly PQCKeyUsage[] = ['decapsulateBits'];
        privKey = await getSubtle().importKey(
          formatJwk,
          keyData,
          algorithm,
          extractable,
          keyUsages
        );
      } else if (skBytes.length === 32) {
        const format = 'raw-seed';
        const algorithm = { name: XWING_ALG_NAME };
        const extractable = false;
        const keyUsages: readonly PQCKeyUsage[] = ['decapsulateBits'];
        privKey = await getSubtle().importKey(
          format as Exclude<KeyFormat, 'jwk'> | 'raw-seed',
          skBytes,
          algorithm,
          extractable,
          keyUsages
        );
      } else {
        throw new Error('Invalid secret key length');
      }
    }

    try {
      const sharedSecret = await getSubtle().decapsulateBits(
        { name: XWING_ALG_NAME },
        privKey,
        cipherText as Uint8Array
      );
      return new Uint8Array(sharedSecret as ArrayBuffer) as TRet<Uint8Array>;
    } catch (e) {
      throw new Error('Native decapsulate failed: ' + (e as Error).message);
    }
  },
};
export const ml_kem768_x25519: TRet<AsyncKEM> = Object.freeze(
  xWingImpl
) as unknown as TRet<AsyncKEM>;

export const XWing: TRet<AsyncKEM> = ml_kem768_x25519;
export const MLKEM768X25519: TRet<AsyncKEM> = ml_kem768_x25519;
