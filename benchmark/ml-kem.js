import { deepStrictEqual } from 'node:assert';
import { compare, utils } from 'micro-bmark';
import {
  kyber512,
  kyber768,
  kyber1024,
  kyber512_90s,
  kyber768_90s,
  kyber1024_90s,
  ml_kem512,
  ml_kem768,
  ml_kem1024,
} from '../ml-kem.js';
import * as ck from 'crystals-kyber';
import * as ckjs from 'crystals-kyber-js';
const ckjs512 = new ckjs.Kyber512();
const ckjs768 = new ckjs.Kyber768();
const ckjs1024 = new ckjs.Kyber1024();
// broken package
// import * as pqck from 'pqc-kyber/pqc_ml-kem.js'; // wasm
import { default as pqcrypto_js } from 'kyber-crystals'; //wasm

// wasm also
import { default as dashline512 } from '@dashlane/pqc-kem-kyber512-node';
import { default as dashline768 } from '@dashlane/pqc-kem-kyber768-node';
import { default as dashline1024 } from '@dashlane/pqc-kem-kyber1024-node';
let dl512, dl768, dl1024;
async function initDashline() {
  dl512 = await dashline512();
  dl768 = await dashline768();
  dl1024 = await dashline1024();
}

const getOpts = (lib) => {
  const { publicKey, secretKey } = lib.keygen();
  const { cipherText, sharedSecret } = lib.encapsulate(publicKey);
  return { publicKey, secretKey, cipherText, sharedSecret };
};

const getNoble = (lib) => ({
  keygen: () => lib.keygen(),
  encrypt: (opts) => lib.encapsulate(opts.publicKey),
  decrypt: (opts) =>
    deepStrictEqual(lib.decapsulate(opts.cipherText, opts.secretKey), opts.sharedSecret),
});

const KYBER = {
  kyber512: {
    opts: getOpts(kyber512),
    dashline: {
      keygen: () => dl512.keypair(),
      encrypt: (opts) => dl512.encapsulate(opts.publicKey),
      decrypt: async (opts) =>
        deepStrictEqual(
          (await dl512.decapsulate(opts.cipherText, opts.secretKey)).sharedSecret,
          opts.sharedSecret
        ),
    },
    ckjs: {
      keygen: async () => await ckjs512.generateKeyPair(),
      encrypt: async (opts) => await ckjs512.encap(opts.publicKey),
      decrypt: async (opts) =>
        deepStrictEqual(await ckjs512.decap(opts.cipherText, opts.secretKey), opts.sharedSecret),
    },
    ck: {
      keygen: () => ck.KeyGen512(),
      encrypt: (opts) => ck.Encrypt512(opts.publicKey),
      decrypt: (opts) =>
        deepStrictEqual(
          Uint8Array.from(ck.Decrypt512(opts.cipherText, opts.secretKey)),
          opts.sharedSecret
        ),
    },
    noble: getNoble(kyber512),
  },
  kyber768: {
    opts: getOpts(kyber768),
    dashline: {
      keygen: () => dl768.keypair(),
      encrypt: (opts) => dl768.encapsulate(opts.publicKey),
      decrypt: async (opts) =>
        deepStrictEqual(
          (await dl768.decapsulate(opts.cipherText, opts.secretKey)).sharedSecret,
          opts.sharedSecret
        ),
    },
    ckjs: {
      keygen: async () => await ckjs768.generateKeyPair(),
      encrypt: async (opts) => await ckjs768.encap(opts.publicKey),
      decrypt: async (opts) =>
        deepStrictEqual(await ckjs768.decap(opts.cipherText, opts.secretKey), opts.sharedSecret),
    },
    ck: {
      keygen: () => ck.KeyGen768(),
      encrypt: (opts) => ck.Encrypt768(opts.publicKey),
      decrypt: (opts) =>
        deepStrictEqual(
          Uint8Array.from(ck.Decrypt768(opts.cipherText, opts.secretKey)),
          opts.sharedSecret
        ),
    },
    noble: getNoble(kyber768),
  },
  kyber1024: {
    opts: getOpts(kyber1024),
    // only 1024
    pqcrypto_js: {
      keygen: () => pqcrypto_js.keyPair(),
      encrypt: (opts) => pqcrypto_js.encrypt(opts.publicKey),
      decrypt: async (opts) =>
        deepStrictEqual(
          await pqcrypto_js.decrypt(opts.cipherText, opts.secretKey),
          opts.sharedSecret
        ),
    },
    dashline: {
      keygen: () => dl1024.keypair(),
      encrypt: (opts) => dl1024.encapsulate(opts.publicKey),
      decrypt: async (opts) =>
        deepStrictEqual(
          (await dl1024.decapsulate(opts.cipherText, opts.secretKey)).sharedSecret,
          opts.sharedSecret
        ),
    },
    ckjs: {
      keygen: async () => await ckjs1024.generateKeyPair(),
      encrypt: async (opts) => await ckjs1024.encap(opts.publicKey),
      decrypt: async (opts) =>
        deepStrictEqual(await ckjs1024.decap(opts.cipherText, opts.secretKey), opts.sharedSecret),
    },
    ck: {
      keygen: () => ck.KeyGen1024(),
      encrypt: (opts) => ck.Encrypt1024(opts.publicKey),
      decrypt: (opts) =>
        deepStrictEqual(
          Uint8Array.from(ck.Decrypt1024(opts.cipherText, opts.secretKey)),
          opts.sharedSecret
        ),
    },
    noble: getNoble(kyber1024),
  },
  kyber512_90s: {
    opts: getOpts(kyber512_90s),
    noble: getNoble(kyber512_90s),
  },
  kyber768_90s: {
    opts: getOpts(kyber768_90s),
    noble: getNoble(kyber768_90s),
  },
  kyber1024_90s: {
    opts: getOpts(kyber1024_90s),
    noble: getNoble(kyber1024_90s),
  },
  'ML-KEM-512': {
    opts: getOpts(ml_kem512),
    noble: getNoble(ml_kem512),
  },
  'ML-KEM-768': {
    opts: getOpts(ml_kem768),
    noble: getNoble(ml_kem768),
  },
  'ML-KEM-1024': {
    opts: getOpts(ml_kem1024),
    noble: getNoble(ml_kem1024),
  },
};
const FNS = ['keygen', 'encrypt', 'decrypt'];

const SAMPLES = 10_000;
export async function main() {
  const onlyNoble = process.argv[2] === 'noble';
  if (onlyNoble) {
    for (const fn of FNS) {
      await compare(
        `==== ${fn} ====`,
        SAMPLES,
        Object.fromEntries(
          Object.entries(KYBER).map(([k, v]) => [k, v.noble[fn].bind(null, v.opts)])
        )
      );
    }
    return;
  }
  await initDashline();
  for (const [algoName, libraries] of Object.entries(KYBER)) {
    for (const fn of FNS) {
      const opts = libraries.opts;
      await compare(
        `==== ${algoName}/${fn} ====`,
        SAMPLES,
        Object.fromEntries(
          Object.entries(libraries)
            .filter(([k, v]) => k !== 'opts')
            .map(([k, v]) => [k, v[fn].bind(null, opts)])
        )
      );
    }
  }
  utils.logMem();
}

// ESM is broken.
import url from 'url';
if (import.meta.url === url.pathToFileURL(process.argv[1]).href) {
  main();
}