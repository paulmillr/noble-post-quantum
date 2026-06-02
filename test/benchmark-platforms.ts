import compare from '@paulmillr/jsbt/bench-compare.js';
import { deepStrictEqual as eql } from 'node:assert';
import url from 'node:url';
import * as jsPlatform from '@awasm/noble/js.js';
import * as noblePlatform from '@awasm/noble/noble.js';
import * as stubs from '@awasm/noble/stub.js';
import * as wasmPlatform from '@awasm/noble/wasm.js';
import * as wasmThreadsPlatform from '@awasm/noble/wasm_threads.js';
import { WP } from '@awasm/noble/workers.js';
import { falcon1024, falcon512 } from '../src/falcon.ts';
import { ml_dsa65 } from '../src/ml-dsa.ts';
import { ml_kem768 } from '../src/ml-kem.ts';
import * as slh from '../src/slh-dsa.ts';

const platforms = {
  noble: noblePlatform,
  js: jsPlatform,
  wasm: wasmPlatform,
  wasm_threads: wasmThreadsPlatform,
};
const platformFns = [
  'sha256',
  'sha512',
  'sha3_256',
  'sha3_512',
  'shake128',
  'shake256',
  'chacha20',
] as const;
let currentPlatform = '';

const install = (name: keyof typeof platforms) => {
  if (currentPlatform === name) return;
  const platform = platforms[name];
  for (const fn of platformFns) stubs[fn].install(platform[fn]);
  currentPlatform = name;
};
const readyThreads = async () => {
  install('wasm_threads');
  await WP.waitOnline();
};
const bytes = (label: string, len: number) => {
  let s = 0x811c9dc5;
  for (let i = 0; i < label.length; i++) s = Math.imul(s ^ label.charCodeAt(i), 0x01000193);
  const out = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    s ^= s << 13;
    s ^= s >>> 17;
    s ^= s << 5;
    out[i] = s;
  }
  return out;
};
const lazy = <T>(fn: () => T) => {
  let value: T | undefined;
  return () => {
    if (value === undefined) value = fn();
    return value;
  };
};
const kem = () => {
  const seed = bytes('ml-kem768-keygen', 64);
  const msg = bytes('ml-kem768-encapsulate', 32);
  const keys = lazy(() => ml_kem768.keygen(seed));
  const enc = lazy(() => ml_kem768.encapsulate(keys().publicKey, msg));
  return {
    keygen: () => ml_kem768.keygen(seed),
    encapsulate: () => ml_kem768.encapsulate(keys().publicKey, msg),
    decapsulate: () => ml_kem768.decapsulate(enc().cipherText, keys().secretKey),
  };
};
const dsa = () => {
  const seed = bytes('ml-dsa65-keygen', 32);
  const msg = bytes('ml-dsa65-message', 32);
  const rand = bytes('ml-dsa65-sign', ml_dsa65.lengths.signRand);
  const keys = lazy(() => ml_dsa65.keygen(seed));
  const signature = lazy(() => ml_dsa65.sign(msg, keys().secretKey, { extraEntropy: rand }));
  return {
    keygen: () => ml_dsa65.keygen(seed),
    sign: () => ml_dsa65.sign(msg, keys().secretKey, { extraEntropy: rand }),
    verify: () => ml_dsa65.verify(signature(), msg, keys().publicKey),
  };
};
const slhdsa = (name: string, lib: typeof slh.slh_dsa_sha2_192f) => {
  const seed = bytes(`${name}-keygen`, lib.lengths.seed);
  const msg = bytes(`${name}-message`, 32);
  const rand = bytes(`${name}-sign`, lib.lengths.signRand);
  const keys = lazy(() => lib.keygen(seed));
  const signature = lazy(() => lib.sign(msg, keys().secretKey, { extraEntropy: rand }));
  return {
    keygen: () => lib.keygen(seed),
    sign: () => lib.sign(msg, keys().secretKey, { extraEntropy: rand }),
    verify: () => lib.verify(signature(), msg, keys().publicKey),
  };
};
const falcon = (name: string, lib: typeof falcon512) => {
  const seed = bytes(`${name}-keygen`, 48);
  const msg = bytes(`${name}-message`, 32);
  const rand = bytes(`${name}-sign`, 48);
  const keys = lazy(() => lib.keygen(seed));
  const signature = lazy(() => lib.sign(msg, keys().secretKey, { extraEntropy: rand }));
  return {
    keygen: () => lib.keygen(seed),
    sign: () => lib.sign(msg, keys().secretKey, { extraEntropy: rand }),
    verify: () => lib.verify(signature(), msg, keys().publicKey),
  };
};
const withPlatforms = (ops: Record<string, () => unknown>) =>
  Object.fromEntries(Object.keys(platforms).map((name) => [name, ops]));
const algorithms = () => {
  install('noble');
  return {
    'ML-KEM768': withPlatforms(kem()),
    'ML-DSA65': withPlatforms(dsa()),
    'SLH-SHA2-192f': withPlatforms(slhdsa('slh-sha2-192f', slh.slh_dsa_sha2_192f)),
    'SLH-SHA2-192s': withPlatforms(slhdsa('slh-sha2-192s', slh.slh_dsa_sha2_192s)),
    'SLH-SHAKE-192f': withPlatforms(slhdsa('slh-shake-192f', slh.slh_dsa_shake_192f)),
    'SLH-SHAKE-192s': withPlatforms(slhdsa('slh-shake-192s', slh.slh_dsa_shake_192s)),
    Falcon512: withPlatforms(falcon('falcon512', falcon512)),
    Falcon1024: withPlatforms(falcon('falcon1024', falcon1024)),
  };
};
async function main() {
  const libs = algorithms();
  await readyThreads();
  const baselines = new Map<string, bigint>();
  const expected = new Map<string, unknown>();
  await compare('Post-Quantum platforms', {}, libs, {
    libDims: ['algorithm', 'platform', 'operation'],
    dims: ['algorithm', 'operation', 'platform'],
    patchArgs: (args, obj) => {
      install(obj.platform);
      // Validate each row immediately before timing it; whole-suite prevalidation
      // changes later ML-KEM/ML-DSA timings through V8/JIT state.
      const key = `${obj.algorithm}/${obj.operation}`;
      const got = libs[obj.algorithm][obj.platform][obj.operation]();
      if (!expected.has(key)) expected.set(key, got);
      else eql(got, expected.get(key));
      return args;
    },
    metrics: {
      'x noble': {
        rev: true,
        width: 7,
        diff: true,
        compute: (obj, stats) => {
          // JSBT dry-run uses a zero mean; keep table-shape checks from dividing by zero.
          if (stats.mean === 0n) return 1;
          const key = `${obj.algorithm}/${obj.operation}`;
          const base = baselines.get(key) || stats.mean;
          if (!baselines.has(key)) baselines.set(key, base);
          return +`${(Number(base) / Number(stats.mean)).toFixed(2)}`;
        },
      },
    },
    prevFile: './test/benchmark-platforms.json',
  });
}

if (import.meta.url === url.pathToFileURL(process.argv[1]).href) main();
