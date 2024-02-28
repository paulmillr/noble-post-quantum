/*! noble-post-quantum - MIT License (c) 2024 Paul Miller (paulmillr.com) */
import { bytes as abytes } from '@noble/hashes/_assert';
import { TypedArray, randomBytes as randb } from '@noble/hashes/utils';

export const ensureBytes = abytes;
export const randomBytes = randb;

// Compares 2 u8a-s in kinda constant time
export function equalBytes(a: Uint8Array, b: Uint8Array) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

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
export function cleanBytes(...list: (TypedArray | TypedArray[])[]) {
  for (const t of list) {
    if (Array.isArray(t)) for (const b of t) b.fill(0);
    else t.fill(0);
  }
}

export function getMask(bits: number) {
  return (1 << bits) - 1; // 4 -> 0b1111
}
