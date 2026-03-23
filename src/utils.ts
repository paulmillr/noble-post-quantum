/**
 * Utilities for hex, bytearray and number handling.
 * @module
 */
/*! noble-post-quantum - MIT License (c) 2024 Paul Miller (paulmillr.com) */
import {
  type CHash,
  type TypedArray,
  abytes,
  abytes as abytes_,
  concatBytes,
  isBytes,
  randomBytes as randb,
} from '@noble/hashes/utils.js';
/**
 * Asserts that a value is a byte array and optionally checks its length.
 * @example
 * Validate that a value is a byte array with the expected length.
 * ```ts
 * abytes(new Uint8Array([1]), 1);
 * ```
 */
const abytesDoc: typeof abytes = abytes;
export { abytesDoc as abytes };
/**
 * Concatenates byte arrays into a new `Uint8Array`.
 * @example
 * Concatenate two byte arrays into one result.
 * ```ts
 * concatBytes(new Uint8Array([1]), new Uint8Array([2]));
 * ```
 */
const concatBytesDoc: typeof concatBytes = concatBytes;
export { concatBytesDoc as concatBytes };
/**
 * Returns cryptographically secure random bytes.
 * @example
 * Generate a fresh random seed.
 * ```ts
 * const seed = randomBytes(4);
 * ```
 */
export const randomBytes: typeof randb = randb;

// Compares 2 u8a-s in kinda constant time
/**
 * Compares two byte arrays in a length-constant way for equal lengths.
 * @param a - First byte array.
 * @param b - Second byte array.
 * @returns Whether both arrays contain the same bytes.
 * @example
 * Compare two byte arrays for equality.
 * ```ts
 * equalBytes(new Uint8Array([1]), new Uint8Array([1]));
 * ```
 */
export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

// copy bytes to new u8a (aligned). Because Buffer.slice is broken.
/**
 * Copies bytes into a fresh `Uint8Array`.
 * @param bytes - Source bytes.
 * @returns Copy of the input bytes.
 * @example
 * Copy bytes into a fresh array.
 * ```ts
 * copyBytes(new Uint8Array([1, 2]));
 * ```
 */
export function copyBytes(bytes: Uint8Array): Uint8Array {
  return Uint8Array.from(bytes);
}

/** Shared key-generation surface for signers and KEMs. */
export type CryptoKeys = {
  /** Optional metadata about the algorithm family or variant. */
  info?: { type?: string };
  /** Public byte lengths for the exported key material. */
  lengths: { seed?: number; publicKey?: number; secretKey?: number };
  /**
   * Generate one secret/public keypair.
   * @param seed - Optional seed bytes for deterministic key generation.
   * @returns Fresh secret/public keypair.
   */
  keygen: (seed?: Uint8Array) => { secretKey: Uint8Array; publicKey: Uint8Array };
  /**
   * Derive one public key from a secret key.
   * @param secretKey - Secret key bytes.
   * @returns Public key bytes.
   */
  getPublicKey: (secretKey: Uint8Array) => Uint8Array;
};

/** Verification options shared by the signature APIs. */
export type VerOpts = {
  /** Optional application-defined context string. */
  context?: Uint8Array;
};
/** Signing options shared by the signature APIs. */
export type SigOpts = VerOpts & {
  // Compatibility with @noble/curves: false to disable, enabled by default, user can pass U8A
  /** Optional extra entropy or `false` to disable randomized signing. */
  extraEntropy?: Uint8Array | false;
};

/**
 * Validates that an options bag is an object and not a byte array.
 * @param opts - Options object to validate.
 * @throws On wrong argument types. {@link TypeError}
 * @example
 * Validate that an options bag is a plain object.
 * ```ts
 * validateOpts({});
 * ```
 */
export function validateOpts(opts: object): void {
  // We try to catch u8a, since it was previously valid argument at this position
  if (typeof opts !== 'object' || opts === null || isBytes(opts))
    throw new TypeError('expected opts to be an object');
}

/**
 * Validates common verification options.
 * @param opts - Verification options. See {@link VerOpts}.
 * @throws On wrong argument types. {@link TypeError}
 * @example
 * Validate common verification options.
 * ```ts
 * validateVerOpts({ context: new Uint8Array([1]) });
 * ```
 */
export function validateVerOpts(opts: VerOpts): void {
  validateOpts(opts);
  if (opts.context !== undefined) abytes(opts.context, undefined, 'opts.context');
}

/**
 * Validates common signing options.
 * @param opts - Signing options. See {@link SigOpts}.
 * @throws On wrong argument types. {@link TypeError}
 * @example
 * Validate common signing options.
 * ```ts
 * validateSigOpts({ extraEntropy: new Uint8Array([1]) });
 * ```
 */
export function validateSigOpts(opts: SigOpts): void {
  validateVerOpts(opts);
  if (opts.extraEntropy !== false && opts.extraEntropy !== undefined)
    abytes(opts.extraEntropy, undefined, 'opts.extraEntropy');
}

/** Generic signature interface with key generation, signing, and verification. */
export type Signer = CryptoKeys & {
  /** Public byte lengths for signatures and signing randomness. */
  lengths: { signRand?: number; signature?: number };
  /**
   * Sign one message.
   * @param msg - Message bytes to sign.
   * @param secretKey - Secret key bytes.
   * @param opts - Optional signing options.
   * @returns Signature bytes.
   */
  sign: (msg: Uint8Array, secretKey: Uint8Array, opts?: SigOpts) => Uint8Array;
  /**
   * Verify one signature.
   * @param sig - Signature bytes.
   * @param msg - Signed message bytes.
   * @param publicKey - Public key bytes.
   * @param opts - Optional verification options.
   * @returns `true` when the signature is valid.
   */
  verify: (sig: Uint8Array, msg: Uint8Array, publicKey: Uint8Array, opts?: VerOpts) => boolean;
};

/** Generic key encapsulation mechanism interface. */
export type KEM = CryptoKeys & {
  /** Public byte lengths for ciphertexts and optional message randomness. */
  lengths: { cipherText?: number; msg?: number; msgRand?: number };
  /**
   * Encapsulate one shared secret to a recipient public key.
   * @param publicKey - Recipient public key bytes.
   * @param msg - Optional caller-provided randomness/message seed.
   * @returns Ciphertext plus shared secret.
   */
  encapsulate: (
    publicKey: Uint8Array,
    msg?: Uint8Array
  ) => {
    cipherText: Uint8Array;
    sharedSecret: Uint8Array;
  };
  /**
   * Recover the shared secret from a ciphertext and recipient secret key.
   * @param cipherText - Ciphertext bytes.
   * @param secretKey - Recipient secret key bytes.
   * @returns Decapsulated shared secret.
   */
  decapsulate: (cipherText: Uint8Array, secretKey: Uint8Array) => Uint8Array;
};

/** Bidirectional encoder/decoder interface. */
export interface Coder<F, T> {
  /**
   * Serialize one value.
   * @param from - Value to encode.
   * @returns Encoded representation.
   */
  encode(from: F): T;
  /**
   * Parse one serialized value.
   * @param to - Encoded representation.
   * @returns Decoded value.
   */
  decode(to: T): F;
}

/** Encoder/decoder interface specialized for byte arrays. */
export interface BytesCoder<T> extends Coder<T, Uint8Array> {
  /**
   * Serialize one value into bytes.
   * @param data - Value to encode.
   * @returns Encoded bytes.
   */
  encode: (data: T) => Uint8Array;
  /**
   * Parse one byte array into a value.
   * @param bytes - Encoded bytes.
   * @returns Decoded value.
   */
  decode: (bytes: Uint8Array) => T;
}

/** Fixed-length byte encoder/decoder. */
export type BytesCoderLen<T> = BytesCoder<T> & { bytesLen: number };

// nano-packed, because struct encoding is hard.
type UnCoder<T> = T extends BytesCoder<infer U> ? U : never;
type SplitOut<T extends (number | BytesCoderLen<any>)[]> = {
  [K in keyof T]: T[K] extends number ? Uint8Array : UnCoder<T[K]>;
};
/**
 * Builds a fixed-layout coder from byte lengths and nested coders.
 * @param label - Label used in validation errors.
 * @param lengths - Field lengths or nested coders.
 * @returns Composite fixed-length coder.
 * @example
 * Build a fixed-layout coder from byte lengths and nested coders.
 * ```ts
 * splitCoder('demo', 1, 2).encode([new Uint8Array([1]), new Uint8Array([2, 3])]);
 * ```
 */
export function splitCoder<T extends (number | BytesCoderLen<any>)[]>(
  label: string,
  ...lengths: T
): BytesCoder<SplitOut<T>> & { bytesLen: number } {
  const getLength = (c: number | BytesCoderLen<any>) => (typeof c === 'number' ? c : c.bytesLen);
  const bytesLen: number = lengths.reduce((sum: number, a) => sum + getLength(a), 0);
  return {
    bytesLen,
    encode: (bufs: T) => {
      const res = new Uint8Array(bytesLen);
      for (let i = 0, pos = 0; i < lengths.length; i++) {
        const c = lengths[i];
        const l = getLength(c);
        const b: Uint8Array = typeof c === 'number' ? (bufs[i] as any) : c.encode(bufs[i]);
        abytes_(b, l, label);
        res.set(b, pos);
        if (typeof c !== 'number') b.fill(0); // clean
        pos += l;
      }
      return res;
    },
    decode: (buf: Uint8Array) => {
      abytes_(buf, bytesLen, label);
      const res = [];
      for (const c of lengths) {
        const l = getLength(c);
        const b = buf.subarray(0, l);
        res.push(typeof c === 'number' ? b : c.decode(b));
        buf = buf.subarray(l);
      }
      return res as SplitOut<T>;
    },
  } as any;
}
// nano-packed.array (fixed size)
/**
 * Builds a fixed-length vector coder from another fixed-length coder.
 * @param c - Element coder.
 * @param vecLen - Number of elements in the vector.
 * @returns Fixed-length vector coder.
 * @example
 * Build a fixed-length vector coder from another fixed-length coder.
 * ```ts
 * vecCoder(
 *   { bytesLen: 1, encode: (n: number) => Uint8Array.of(n), decode: (b: Uint8Array) => b[0] || 0 },
 *   2
 * ).encode([1, 2]);
 * ```
 */
export function vecCoder<T>(c: BytesCoderLen<T>, vecLen: number): BytesCoderLen<T[]> {
  const bytesLen = vecLen * c.bytesLen;
  return {
    bytesLen,
    encode: (u: T[]): Uint8Array => {
      if (u.length !== vecLen)
        throw new RangeError(`vecCoder.encode: wrong length=${u.length}. Expected: ${vecLen}`);
      const res = new Uint8Array(bytesLen);
      for (let i = 0, pos = 0; i < u.length; i++) {
        const b = c.encode(u[i]);
        res.set(b, pos);
        b.fill(0); // clean
        pos += b.length;
      }
      return res;
    },
    decode: (a: Uint8Array): T[] => {
      abytes_(a, bytesLen);
      const r: T[] = [];
      for (let i = 0; i < a.length; i += c.bytesLen)
        r.push(c.decode(a.subarray(i, i + c.bytesLen)));
      return r;
    },
  };
}

// cleanBytes(Uint8Array.of(), [Uint16Array.of(), Uint32Array.of()])
/**
 * Overwrites typed arrays with zeroes.
 * @param list - Typed arrays or lists of typed arrays to clear.
 * @example
 * Overwrite typed arrays with zeroes.
 * ```ts
 * const buf = Uint8Array.of(1, 2, 3);
 * cleanBytes(buf);
 * ```
 */
export function cleanBytes(...list: (TypedArray | TypedArray[])[]): void {
  for (const t of list) {
    if (Array.isArray(t)) for (const b of t) b.fill(0);
    else t.fill(0);
  }
}

/**
 * Creates a mask with the lowest `bits` bits set.
 * @param bits - Number of low bits to keep.
 * @returns Bit mask with `bits` ones.
 * @example
 * Create a low-bit mask for packed-field operations.
 * ```ts
 * const mask = getMask(4);
 * ```
 */
export function getMask(bits: number): number {
  return (1 << bits) - 1; // 4 -> 0b1111
}

/** Shared empty byte array used as the default context. */
export const EMPTY: Uint8Array = /* @__PURE__ */ Uint8Array.of();

/**
 * Builds the domain-separated message prefix for direct signing.
 * @param msg - Message bytes.
 * @param ctx - Optional context bytes.
 * @returns Domain-separated message payload.
 * @throws On wrong argument ranges or values. {@link RangeError}
 * @example
 * Build the domain-separated payload before direct signing.
 * ```ts
 * const payload = getMessage(new Uint8Array([1, 2]));
 * ```
 */
export function getMessage(msg: Uint8Array, ctx: Uint8Array = EMPTY): Uint8Array {
  abytes_(msg);
  abytes_(ctx);
  if (ctx.length > 255) throw new RangeError('context should be less than 255 bytes');
  return concatBytes(new Uint8Array([0, ctx.length]), ctx, msg);
}

// 06 09 60 86 48 01 65 03 04 02
const oidNistP = /* @__PURE__ */ Uint8Array.from([6, 9, 0x60, 0x86, 0x48, 1, 0x65, 3, 4, 2]);

/**
 * Validates that a hash exposes a NIST hash OID and enough collision resistance.
 * @param hash - Hash function to validate.
 * @param requiredStrength - Minimum required collision-resistance strength in bits.
 * @throws If the hash metadata or collision resistance is insufficient. {@link Error}
 * @example
 * Validate that a hash exposes a NIST hash OID and enough collision resistance.
 * ```ts
 * import { sha256 } from '@noble/hashes/sha2.js';
 * import { checkHash } from '@noble/post-quantum/utils.js';
 * checkHash(sha256, 128);
 * ```
 */
export function checkHash(hash: CHash, requiredStrength: number = 0): void {
  if (!hash.oid || !equalBytes(hash.oid.subarray(0, 10), oidNistP))
    throw new Error('hash.oid is invalid: expected NIST hash');
  const collisionResistance = (hash.outputLen * 8) / 2;
  if (requiredStrength > collisionResistance) {
    throw new Error(
      'Pre-hash security strength too low: ' +
        collisionResistance +
        ', required: ' +
        requiredStrength
    );
  }
}

/**
 * Builds the domain-separated prehash message payload for signature schemes with external hashing.
 * @param hash - Prehash function.
 * @param msg - Message bytes.
 * @param ctx - Optional context bytes.
 * @returns Domain-separated prehash payload.
 * @throws On wrong argument ranges or values. {@link RangeError}
 * @example
 * Build the domain-separated prehash payload for external hashing.
 * ```ts
 * import { sha256 } from '@noble/hashes/sha2.js';
 * import { getMessagePrehash } from '@noble/post-quantum/utils.js';
 * getMessagePrehash(sha256, new Uint8Array([1, 2]));
 * ```
 */
export function getMessagePrehash(
  hash: CHash,
  msg: Uint8Array,
  ctx: Uint8Array = EMPTY
): Uint8Array {
  abytes_(msg);
  abytes_(ctx);
  if (ctx.length > 255) throw new RangeError('context should be less than 255 bytes');
  const hashed = hash(msg);
  return concatBytes(new Uint8Array([1, ctx.length]), ctx, hash.oid!, hashed);
}
