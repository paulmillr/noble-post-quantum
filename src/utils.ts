/**
 * Utilities for hex, bytearray and number handling.
 * @module
 */
/*! noble-post-quantum - MIT License (c) 2024 Paul Miller (paulmillr.com) */
import { abytes } from '@noble/hashes/_assert';
import { sha224, sha256 } from '@noble/hashes/sha256';
import { sha3_224, sha3_256, sha3_384, sha3_512, shake128, shake256 } from '@noble/hashes/sha3';
import { sha384, sha512, sha512_224, sha512_256 } from '@noble/hashes/sha512';
import {
  type TypedArray,
  concatBytes,
  hexToBytes,
  randomBytes as randb,
  utf8ToBytes,
} from '@noble/hashes/utils';

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

/** Generic interface for signatures. Has keygen, sign and verify. */
export type Signer = {
  signRandBytes: number;
  keygen: (seed: Uint8Array) => {
    secretKey: Uint8Array;
    publicKey: Uint8Array;
  };
  sign: (secretKey: Uint8Array, msg: Uint8Array, random?: Uint8Array) => Uint8Array;
  verify: (publicKey: Uint8Array, msg: Uint8Array, sig: Uint8Array) => boolean;
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

// OIDS from https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration
// TODO: maybe add 'OID' property to hashes themselves to improve tree-shaking?
const HASHES: Record<string, { oid: Uint8Array; hash: (msg: Uint8Array) => Uint8Array }> = {
  'SHA2-256': { oid: hexToBytes('0609608648016503040201'), hash: sha256 },
  'SHA2-384': { oid: hexToBytes('0609608648016503040202'), hash: sha384 },
  'SHA2-512': { oid: hexToBytes('0609608648016503040203'), hash: sha512 },
  'SHA2-224': { oid: hexToBytes('0609608648016503040204'), hash: sha224 },
  'SHA2-512/224': { oid: hexToBytes('0609608648016503040205'), hash: sha512_224 },
  'SHA2-512/256': { oid: hexToBytes('0609608648016503040206'), hash: sha512_256 },
  'SHA3-224': { oid: hexToBytes('0609608648016503040207'), hash: sha3_224 },
  'SHA3-256': { oid: hexToBytes('0609608648016503040208'), hash: sha3_256 },
  'SHA3-384': { oid: hexToBytes('0609608648016503040209'), hash: sha3_384 },
  'SHA3-512': { oid: hexToBytes('060960864801650304020A'), hash: sha3_512 },
  'SHAKE-128': {
    oid: hexToBytes('060960864801650304020B'),
    hash: (msg) => shake128(msg, { dkLen: 32 }),
  },
  'SHAKE-256': {
    oid: hexToBytes('060960864801650304020C'),
    hash: (msg) => shake256(msg, { dkLen: 64 }),
  },
};

export function getMessagePrehash(
  hashName: string,
  msg: Uint8Array,
  ctx: Uint8Array = EMPTY
): Uint8Array {
  ensureBytes(msg);
  ensureBytes(ctx);
  if (ctx.length > 255) throw new Error('context should be less than 255 bytes');
  if (!HASHES[hashName]) throw new Error('unknown hash: ' + hashName);
  const { oid, hash } = HASHES[hashName];
  const hashed = hash(msg);
  return concatBytes(new Uint8Array([1, ctx.length]), ctx, oid, hashed);
}
