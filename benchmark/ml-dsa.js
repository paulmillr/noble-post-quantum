import { deepStrictEqual } from 'node:assert';
import { compare, utils } from 'micro-bmark';
import {
  ml_dsa44,
  ml_dsa65,
  ml_dsa87,
} from '../ml-dsa.js';
const seed = new Uint8Array(32).fill(1);
const msg = new Uint8Array(32).fill(2);

const getOpts = (lib) => {
  const { publicKey, secretKey } = lib.keygen(seed);
  const signature = lib.sign(secretKey, msg);
  return { publicKey, secretKey, signature };
};

const getNoble = (lib) => ({
  keygen: () => lib.keygen(),
  sign: (opts) => deepStrictEqual(lib.sign(opts.secretKey, msg), opts.signature),
  verify: (opts) => deepStrictEqual(lib.verify(opts.publicKey, msg, opts.signature), true),
});

const MLDSA = {
  'v44': {
    opts: getOpts(ml_dsa44),
    noble: getNoble(ml_dsa44),
  },
  'v65': {
    opts: getOpts(ml_dsa65),
    noble: getNoble(ml_dsa65),
  },
  'v87': {
    opts: getOpts(ml_dsa87),
    noble: getNoble(ml_dsa87),
  },
};
const FNS = ['keygen', 'sign', 'verify'];

export async function main() {
  await compare('keygen', 100, {
    'ML-DSA44': () => {
      MLDSA.v44.noble.keygen();
    },
    'ML-DSA65': () => {
      MLDSA.v65.noble.keygen();
    },
    'ML-DSA87': () => {
      MLDSA.v87.noble.keygen();
    },
  });
  await compare('sign', 100, {
    'ML-DSA44': () => {
      MLDSA.v44.noble.sign(MLDSA.v44.opts);
    },
    'ML-DSA65': () => {
      MLDSA.v65.noble.sign(MLDSA.v65.opts);
    },
    'ML-DSA87': () => {
      MLDSA.v87.noble.sign(MLDSA.v87.opts);
    },
  });
  await compare('verify', 100, {
    'ML-DSA44': () => {
      MLDSA.v44.noble.verify(MLDSA.v44.opts);
    },
    'ML-DSA65': () => {
      MLDSA.v65.noble.verify(MLDSA.v65.opts);
    },
    'ML-DSA87': () => {
      MLDSA.v87.noble.verify(MLDSA.v87.opts);
    },
  });
  utils.logMem();
}

// ESM is broken.
import url from 'node:url';
if (import.meta.url === url.pathToFileURL(process.argv[1]).href) {
  main();
}
