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
export { abytes } from '@noble/hashes/utils.js';
export { concatBytes };
export const randomBytes: typeof randb = randb;

// Compares 2 u8a-s in kinda constant time
export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

// copy bytes to new u8a (aligned). Because Buffer.slice is broken.
export function copyBytes(bytes: Uint8Array): Uint8Array {
  return Uint8Array.from(bytes);
}

export type CryptoKeys = {
  info?: { type?: string };
  lengths: { seed?: number; publicKey?: number; secretKey?: number };
  keygen: (seed?: Uint8Array) => { secretKey: Uint8Array; publicKey: Uint8Array };
  getPublicKey: (secretKey: Uint8Array) => Uint8Array;
};

export type VerOpts = {
  context?: Uint8Array;
};
export type SigOpts = VerOpts & {
  // Compatibility with @noble/curves: false to disable, enabled by default, user can pass U8A
  extraEntropy?: Uint8Array | false;
};

export function validateOpts(opts: object): void {
  // We try to catch u8a, since it was previously valid argument at this position
  if (typeof opts !== 'object' || opts === null || isBytes(opts))
    throw new Error('expected opts to be an object');
}

export function validateVerOpts(opts: VerOpts): void {
  validateOpts(opts);
  if (opts.context !== undefined) abytes(opts.context, undefined, 'opts.context');
}

export function validateSigOpts(opts: SigOpts): void {
  validateVerOpts(opts);
  if (opts.extraEntropy !== false && opts.extraEntropy !== undefined)
    abytes(opts.extraEntropy, undefined, 'opts.extraEntropy');
}

/** Generic interface for signatures. Has keygen, sign and verify. */
export type Signer = CryptoKeys & {
  lengths: { signRand?: number; signature?: number };
  sign: (msg: Uint8Array, secretKey: Uint8Array, opts?: SigOpts) => Uint8Array;
  verify: (sig: Uint8Array, msg: Uint8Array, publicKey: Uint8Array, opts?: VerOpts) => boolean;
};

export type KEM = CryptoKeys & {
  lengths: { cipherText?: number; msg?: number; msgRand?: number };
  encapsulate: (
    publicKey: Uint8Array,
    msg?: Uint8Array
  ) => {
    cipherText: Uint8Array;
    sharedSecret: Uint8Array;
  };
  decapsulate: (cipherText: Uint8Array, secretKey: Uint8Array) => Uint8Array;
};

export interface Coder<F, T> {
  encode(from: F): T;
  decode(to: T): F;
}

export interface BytesCoder<T> extends Coder<T, Uint8Array> {
  encode: (data: T) => Uint8Array;
  decode: (bytes: Uint8Array) => T;
}

export type BytesCoderLen<T> = BytesCoder<T> & { bytesLen: number };

// nano-packed, because struct encoding is hard.
type UnCoder<T> = T extends BytesCoder<infer U> ? U : never;
type SplitOut<T extends (number | BytesCoderLen<any>)[]> = {
  [K in keyof T]: T[K] extends number ? Uint8Array : UnCoder<T[K]>;
};
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
export function vecCoder<T>(c: BytesCoderLen<T>, vecLen: number): BytesCoderLen<T[]> {
  const bytesLen = vecLen * c.bytesLen;
  return {
    bytesLen,
    encode: (u: T[]): Uint8Array => {
      if (u.length !== vecLen)
        throw new Error(`vecCoder.encode: wrong length=${u.length}. Expected: ${vecLen}`);
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
export function cleanBytes(...list: (TypedArray | TypedArray[])[]): void {
  for (const t of list) {
    if (Array.isArray(t)) for (const b of t) b.fill(0);
    else t.fill(0);
  }
}

export function getMask(bits: number): number {
  return (1 << bits) - 1; // 4 -> 0b1111
}

export const EMPTY: Uint8Array = Uint8Array.of();

export function getMessage(msg: Uint8Array, ctx: Uint8Array = EMPTY): Uint8Array {
  abytes_(msg);
  abytes_(ctx);
  if (ctx.length > 255) throw new Error('context should be less than 255 bytes');
  return concatBytes(new Uint8Array([0, ctx.length]), ctx, msg);
}

// 06 09 60 86 48 01 65 03 04 02
const oidNistP = /* @__PURE__ */ Uint8Array.from([6, 9, 0x60, 0x86, 0x48, 1, 0x65, 3, 4, 2]);

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

export function getMessagePrehash(
  hash: CHash,
  msg: Uint8Array,
  ctx: Uint8Array = EMPTY
): Uint8Array {
  abytes_(msg);
  abytes_(ctx);
  if (ctx.length > 255) throw new Error('context should be less than 255 bytes');
  const hashed = hash(msg);
  return concatBytes(new Uint8Array([1, ctx.length]), ctx, hash.oid!, hashed);
}
