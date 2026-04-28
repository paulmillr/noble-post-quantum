/**
 * Crucible harness for noble-post-quantum.
 * Repo: https://github.com/symbolicsoft/crucible
 * Purpose: expose Crucible's stdin/stdout JSON-lines protocol for the full ML-KEM and ML-DSA
 * batteries against this repo's implementation.
 * Usage:
 *   node test/crucible.ts
 *   <crucible-repo>/target/debug/crucible node /abs/path/test/crucible.ts
 *   <crucible-repo>/target/debug/crucible node /abs/path/test/crucible.ts --battery ml-dsa
 */
import { bytesToHex, hexToBytes, u8 } from '@awasm/noble/utils.js';
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '../src/ml-dsa.ts';
import { __tests as mlKemTests, ml_kem1024, ml_kem512, ml_kem768 } from '../src/ml-kem.ts';

export type Req = {
  function: string;
  inputs?: Record<string, string>;
  params?: Record<string, number>;
};

export type Res = {
  outputs?: Record<string, string>;
  error?: string;
  unsupported?: boolean;
};

const KEMS = {
  512: ml_kem512,
  768: ml_kem768,
  1024: ml_kem1024,
} as const;
const DSAS = {
  44: ml_dsa44,
  65: ml_dsa65,
  87: ml_dsa87,
} as const;
type DsaInternal = {
  sign(
    msg: Uint8Array,
    secretKey: Uint8Array,
    opts?: { extraEntropy?: Uint8Array | false; externalMu?: boolean }
  ): Uint8Array;
  verify(
    sig: Uint8Array,
    msg: Uint8Array,
    publicKey: Uint8Array,
    opts?: { externalMu?: boolean }
  ): boolean;
};
const KEM_BY_PK = new Map(Object.values(KEMS).map((kem) => [kem.lengths.publicKey, kem] as const));
const KEM_BY_SK = new Map(Object.values(KEMS).map((kem) => [kem.lengths.secretKey, kem] as const));
const DSA_BY_PK = new Map(Object.values(DSAS).map((dsa) => [dsa.lengths.publicKey, dsa] as const));
const DSA_BY_SK = new Map(Object.values(DSAS).map((dsa) => [dsa.lengths.secretKey, dsa] as const));
const DSA_BY_SIG = new Map(Object.values(DSAS).map((dsa) => [dsa.lengths.signature, dsa] as const));

const print = (value: unknown) =>
  new Promise<void>((resolve, reject) => {
    process.stdout.write(`${JSON.stringify(value)}\n`, (error) => {
      if (error) reject(error);
      else resolve();
    });
  });
const ok = (outputs: Record<string, string>): Res => ({ outputs });
const err = (error: string): Res => ({ error });
const unsupported = (): Res => ({ unsupported: true });
const getBytes = (req: Req, key: string) => {
  const hex = req.inputs?.[key];
  if (hex === undefined) throw new Error(`missing input '${key}'`);
  return hexToBytes(hex);
};
const getInt = (req: Req, key: string) => {
  const n = req.params?.[key];
  if (n === undefined) throw new Error(`missing param '${key}'`);
  return n;
};
const getDsa = (
  paramSet: number | undefined,
  key?: Uint8Array,
  kind: 'key' | 'pk' | 'sk' = 'key'
) => {
  // Crucible only passes `param_set` to `ML_DSA_KeyGen`; `ML_DSA_Sign` / `ML_DSA_Verify`
  // infer the preset from key length. That means malformed key-size tests can fail here in
  // harness routing before the real ML-DSA implementation sees the request. For verify, also
  // fall back to the unique ML-DSA signature lengths so malformed public-key lengths still reach
  // the real verifier when the signature shape identifies the preset.
  if (paramSet === 44 || paramSet === 65 || paramSet === 87) return DSAS[paramSet];
  if (!key) throw new Error(`missing ${kind}`);
  const dsa = (kind === 'pk' ? DSA_BY_PK : DSA_BY_SK).get(key.length);
  if (!dsa) throw new Error(`unsupported ${kind} length: ${key.length}`);
  return dsa;
};
const getDsaVerify = (paramSet: number | undefined, pk: Uint8Array, sig: Uint8Array) => {
  if (paramSet === 44 || paramSet === 65 || paramSet === 87) return DSAS[paramSet];
  const byPk = DSA_BY_PK.get(pk.length);
  if (byPk) return byPk;
  const bySig = DSA_BY_SIG.get(sig.length);
  if (bySig) return bySig;
  throw new Error(
    `cannot infer ML-DSA param_set from pk length ${pk.length} or signature length ${sig.length}`
  );
};
const getDsaInternal = (
  paramSet: number | undefined,
  key?: Uint8Array,
  kind: 'key' | 'pk' | 'sk' = 'key'
) => (getDsa(paramSet, key, kind) as typeof ml_dsa44 & { internal: DsaInternal }).internal;
const getKemByPk = (pk: Uint8Array) => {
  const kem = KEM_BY_PK.get(pk.length);
  if (!kem) throw new Error(`invalid ek length: ${pk.length}`);
  return kem;
};
const getKemBySk = (sk: Uint8Array) => {
  const kem = KEM_BY_SK.get(sk.length);
  if (!kem) throw new Error(`invalid dk length: ${sk.length}`);
  return kem;
};
const coeffFromBytes = (bytes: Uint8Array, name: string) => {
  if (!bytes.length || bytes.length > 2)
    throw new Error(`${name} must be 1 or 2 bytes, got ${bytes.length}`);
  const coeff = new Uint16Array(1);
  u8(coeff).set(bytes);
  return coeff[0];
};
const coeffToHex = (n: number) => bytesToHex(u8(Uint16Array.of(n)));
const polyFromBytes = (bytes: Uint8Array, name: string) => {
  if (bytes.length !== 512) throw new Error(`${name} must be 512 bytes, got ${bytes.length}`);
  return new Uint16Array(bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength));
};

export const handle = (req: Req): Res => {
  if (typeof req.function !== 'string' || !req.function) return err("missing input 'function'");
  switch (req.function) {
    case 'Compress_d': {
      const d = getInt(req, 'd');
      const x = coeffFromBytes(getBytes(req, 'x'), 'x');
      return ok({ y: coeffToHex(mlKemTests.Compress_d(x, d)) });
    }
    case 'Decompress_d': {
      const d = getInt(req, 'd');
      const y = coeffFromBytes(getBytes(req, 'y'), 'y');
      return ok({ x: coeffToHex(mlKemTests.Decompress_d(y, d)) });
    }
    case 'ByteEncode_d': {
      const d = getInt(req, 'd');
      const F = polyFromBytes(getBytes(req, 'F'), 'F');
      return ok({ B: bytesToHex(mlKemTests.ByteEncode_d(F, d)) });
    }
    case 'ByteDecode_d': {
      const d = getInt(req, 'd');
      const B = getBytes(req, 'B');
      return ok({ F: bytesToHex(u8(mlKemTests.ByteDecode_d(B, d))) });
    }
    case 'NTT': {
      const f = polyFromBytes(getBytes(req, 'f'), 'f');
      return ok({ f_hat: bytesToHex(u8(mlKemTests.NTT(f))) });
    }
    case 'NTT_inv': {
      const fHat = polyFromBytes(getBytes(req, 'f_hat'), 'f_hat');
      return ok({ f: bytesToHex(u8(mlKemTests.NTT_inv(fHat))) });
    }
    case 'MultiplyNTTs': {
      const fHat = polyFromBytes(getBytes(req, 'f_hat'), 'f_hat');
      const gHat = polyFromBytes(getBytes(req, 'g_hat'), 'g_hat');
      return ok({ h_hat: bytesToHex(u8(mlKemTests.MultiplyNTTs(fHat, gHat))) });
    }
    case 'SamplePolyCBD': {
      const eta = getInt(req, 'eta');
      const B = getBytes(req, 'B');
      return ok({ f: bytesToHex(u8(mlKemTests.SamplePolyCBD(B, eta))) });
    }
    case 'SampleNTT': {
      const B = getBytes(req, 'B');
      return ok({ a_hat: bytesToHex(u8(mlKemTests.SampleNTT(B))) });
    }
    case 'ML_KEM_KeyGen': {
      const randomness = getBytes(req, 'randomness');
      const paramSet = getInt(req, 'param_set');
      const kem = KEMS[paramSet as keyof typeof KEMS];
      if (!kem) throw new Error(`unsupported param_set: ${paramSet}`);
      const { publicKey, secretKey } = kem.keygen(randomness);
      return ok({ ek: bytesToHex(publicKey), dk: bytesToHex(secretKey) });
    }
    case 'ML_KEM_Encaps': {
      const ek = getBytes(req, 'ek');
      const randomness = getBytes(req, 'randomness');
      const kem = getKemByPk(ek);
      const { cipherText, sharedSecret } = kem.encapsulate(ek, randomness);
      return ok({ c: bytesToHex(cipherText), K: bytesToHex(sharedSecret) });
    }
    case 'ML_KEM_Decaps': {
      const c = getBytes(req, 'c');
      const dk = getBytes(req, 'dk');
      const kem = getKemBySk(dk);
      return ok({ K: bytesToHex(kem.decapsulate(c, dk)) });
    }
    case 'ML_DSA_KeyGen': {
      const seed = getBytes(req, 'seed');
      const paramSet = getInt(req, 'param_set');
      const dsa = DSAS[paramSet as keyof typeof DSAS];
      if (!dsa) throw new Error(`unsupported param_set: ${paramSet}`);
      const { publicKey, secretKey } = dsa.keygen(seed);
      return ok({ pk: bytesToHex(publicKey), sk: bytesToHex(secretKey) });
    }
    case 'ML_DSA_Sign': {
      const sk = getBytes(req, 'sk');
      const message = getBytes(req, 'message');
      const rnd = getBytes(req, 'rnd');
      // Crucible's README says `sigma`, but the battery code actually looks for `signature`.
      // Crucible checks Algorithm 7 / 8 internal behavior on the raw message bytes.
      // The public noble API prepends context framing first, so the harness must use the
      // internal ML-DSA surface here to stay byte-compatible with Crucible's reference.
      const dsa = getDsaInternal(req.params?.param_set, sk, 'sk');
      const signature = dsa.sign(message, sk, { extraEntropy: rnd });
      const hex = bytesToHex(signature);
      return ok({ signature: hex, sigma: hex });
    }
    case 'ML_DSA_Verify': {
      const pk = getBytes(req, 'pk');
      const message = getBytes(req, 'message');
      // Accept both names so the harness works against the battery code and the README examples.
      const sigmaHex = req.inputs?.sigma || req.inputs?.signature;
      if (!sigmaHex) throw new Error("missing input 'sigma'");
      const sigma = hexToBytes(sigmaHex);
      const dsa = (
        getDsaVerify(req.params?.param_set, pk, sigma) as typeof ml_dsa44 & {
          internal: DsaInternal;
        }
      ).internal;
      return ok({ valid: dsa.verify(sigma, message, pk) ? '01' : '00' });
    }
    default:
      return unsupported();
  }
};

export const handshake = {
  implementation: 'noble-post-quantum',
  functions: [
    'Compress_d',
    'Decompress_d',
    'ByteEncode_d',
    'ByteDecode_d',
    'NTT',
    'NTT_inv',
    'MultiplyNTTs',
    'SamplePolyCBD',
    'SampleNTT',
    'ML_KEM_KeyGen',
    'ML_KEM_Encaps',
    'ML_KEM_Decaps',
    'ML_DSA_KeyGen',
    'ML_DSA_Sign',
    'ML_DSA_Verify',
  ],
} as const;

export const main = async () => {
  await print(handshake);
  const rl = createInterface({ input: process.stdin, crlfDelay: Infinity });
  for await (const line of rl) {
    const trimmed = line.trim();
    if (!trimmed) break;
    try {
      await print(handle(JSON.parse(trimmed)));
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error);
      await print(err(msg));
    }
  }
};

if (process.argv[1] === fileURLToPath(import.meta.url)) await main();
