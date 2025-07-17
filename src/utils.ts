/**
 * Utilities for hex, bytearray and number handling.
 * @module
 */
/*! noble-post-quantum - MIT License (c) 2024 Paul Miller (paulmillr.com) */
import {
  type CHash,
  type TypedArray,
  abytes,
  concatBytes,
  randomBytes as randb,
  utf8ToBytes,
} from '@noble/hashes/utils.js';

export const ensureBytes: typeof abytes = abytes;
export const randomBytes: typeof randb = randb;
export { concatBytes, utf8ToBytes };

// Compares 2 u8a-s in kinda constant time
export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

export type CryptoKeys = {
  info: { lengths: { seed?: number; public?: number; secret?: number } };
  keygen: (seed?: Uint8Array) => { secretKey: Uint8Array; publicKey: Uint8Array };
  getPublicKey: (secretKey: Uint8Array) => Uint8Array;
};

/** Generic interface for signatures. Has keygen, sign and verify. */
export type Signer = CryptoKeys & {
  info: { lengths: { signRand?: number; signature?: number } };
  sign: (
    msg: Uint8Array,
    secretKey: Uint8Array,
    ctx?: Uint8Array,
    random?: Uint8Array
  ) => Uint8Array;
  verify: (sig: Uint8Array, msg: Uint8Array, publicKey: Uint8Array, ctx?: Uint8Array) => boolean;
};

export type KEM = CryptoKeys & {
  info: { lengths: { cipherText?: number; msg?: number } };
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
        ensureBytes(b, l);
        res.set(b, pos);
        if (typeof c !== 'number') b.fill(0); // clean
        pos += l;
      }
      return res;
    },
    decode: (buf: Uint8Array) => {
      ensureBytes(buf, bytesLen);
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
      ensureBytes(a, bytesLen);
      const r: T[] = [];
      for (let i = 0; i < a.length; i += c.bytesLen)
        r.push(c.decode(a.subarray(i, i + c.bytesLen)));
      return r;
    },
  };
}

// cleanBytes(new Uint8Array(), [new Uint16Array(), new Uint32Array()])
export function cleanBytes(...list: (TypedArray | TypedArray[])[]): void {
  for (const t of list) {
    if (Array.isArray(t)) for (const b of t) b.fill(0);
    else t.fill(0);
  }
}

export function getMask(bits: number): number {
  return (1 << bits) - 1; // 4 -> 0b1111
}

export const EMPTY: Uint8Array = new Uint8Array(0);

export function getMessage(msg: Uint8Array, ctx: Uint8Array = EMPTY): Uint8Array {
  ensureBytes(msg);
  ensureBytes(ctx);
  if (ctx.length > 255) throw new Error('context should be less than 255 bytes');
  return concatBytes(new Uint8Array([0, ctx.length]), ctx, msg);
}

export function getMessagePrehash(
  hash: CHash,
  msg: Uint8Array,
  ctx: Uint8Array = EMPTY,
  requiredStrength: number = 0
): Uint8Array {
  ensureBytes(msg);
  ensureBytes(ctx);
  if (ctx.length > 255) throw new Error('context should be less than 255 bytes');
  // check for NIST prefix
  if (
    !hash.oid ||
    !equalBytes(hash.oid.subarray(0, 10), new Uint8Array([6, 9, 96, 134, 72, 1, 101, 3, 4, 2]))
  ) {
    throw new Error('hash.oid is invalid: expected NIST hash');
  }
  const collisionResistance = (hash.outputLen * 8) / 2;
  if (requiredStrength > collisionResistance) {
    throw new Error(
      'Pre-hash security strength too low: ' +
        collisionResistance +
        ', required: ' +
        requiredStrength
    );
  }
  const hashed = hash(msg);
  return concatBytes(new Uint8Array([1, ctx.length]), ctx, hash.oid, hashed);
}
