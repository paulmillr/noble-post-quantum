import { deepStrictEqual } from 'node:assert';
import { compare, utils } from 'micro-bmark';
import {
  dilithium_v30,
  dilithium_v31,
  ml_dsa44,
  ml_dsa65,
  ml_dsa87,
  dilithium_v31_aes,
} from '../ml-dsa.js';

import * as asanrom from '@asanrom/dilithium';
import * as theqrl from '@theqrl/dilithium5';

// wasm
import { default as dashline2 } from '@dashlane/pqc-sign-dilithium2-node';
import { default as dashline3 } from '@dashlane/pqc-sign-dilithium3-node';
import { default as dashline5 } from '@dashlane/pqc-sign-dilithium5-node';
let dl2, dl3, dl5;
async function initDashline() {
  dl2 = await dashline2();
  dl3 = await dashline3();
  dl5 = await dashline5();
}

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

const getAsanrom = (n) => {
  const level = asanrom.DilithiumLevel.get(n);
  return {
    keygen: () => asanrom.DilithiumKeyPair.generate(level),
    sign: (opts) => {
      deepStrictEqual(
        asanrom.DilithiumPrivateKey.fromBytes(opts.secretKey, level).sign(msg).getBytes(),
        opts.signature
      );
    },
    verify: (opts) => {
      deepStrictEqual(
        asanrom.DilithiumPublicKey.fromBytes(opts.publicKey, level).verifySignature(
          msg,
          asanrom.DilithiumSignature.fromBytes(opts.signature, level)
        ),
        true
      );
    },
  };
};

const getDashline = (fn) => {
  return {
    keygen: async () => await fn().keypair(),
    sign: async (opts) =>
      deepStrictEqual((await fn().sign(msg, opts.secretKey)).signature, opts.signature),
    verify: async (opts) =>
      deepStrictEqual(await fn().verify(opts.signature, msg, opts.publicKey), true),
  };
};

const DILITHIUM = {
  dilithium_v30_2: {
    opts: getOpts(dilithium_v30.dilithium2),
    asanrom: getAsanrom(2),
    noble: getNoble(dilithium_v30.dilithium2),
  },
  dilithium_v30_3: {
    opts: getOpts(dilithium_v30.dilithium3),
    asanrom: getAsanrom(3),
    noble: getNoble(dilithium_v30.dilithium3),
  },
  dilithium_v30_5: {
    opts: getOpts(dilithium_v30.dilithium5),
    asanrom: getAsanrom(5),
    noble: getNoble(dilithium_v30.dilithium5),
  },
  dilithium_v31_2: {
    opts: getOpts(dilithium_v31.dilithium2),
    dashline: getDashline(() => dl2),
    noble: getNoble(dilithium_v31.dilithium2),
  },
  dilithium_v31_3: {
    opts: getOpts(dilithium_v31.dilithium3),
    dashline: getDashline(() => dl3),
    noble: getNoble(dilithium_v31.dilithium3),
  },
  dilithium_v31_5: {
    opts: getOpts(dilithium_v31.dilithium5),
    dashline: getDashline(() => dl5),
    theqrl: {
      keygen: () => {
        const pk = new Uint8Array(theqrl.CryptoPublicKeyBytes);
        const sk = new Uint8Array(theqrl.CryptoSecretKeyBytes);
        theqrl.cryptoSignKeypair(Buffer.from(seed), pk, sk);
      },
      sign: (opts) =>
        deepStrictEqual(
          theqrl
            .cryptoSign(Buffer.from(msg), Buffer.from(opts.secretKey), false)
            .subarray(0, -msg.length),
          opts.signature
        ),
      verify: (opts) =>
        deepStrictEqual(
          theqrl.cryptoSignVerify(
            Buffer.from(opts.signature),
            Buffer.from(msg),
            Buffer.from(opts.publicKey)
          ),
          true
        ),
    },
    noble: getNoble(dilithium_v31.dilithium5),
  },
  dilithium_v31_aes_2: {
    opts: getOpts(dilithium_v31_aes.dilithium2),
    noble: getNoble(dilithium_v31_aes.dilithium2),
  },
  dilithium_v31_aes_3: {
    opts: getOpts(dilithium_v31_aes.dilithium3),
    noble: getNoble(dilithium_v31_aes.dilithium3),
  },
  dilithium_v31_aes_5: {
    opts: getOpts(dilithium_v31_aes.dilithium5),
    noble: getNoble(dilithium_v31_aes.dilithium5),
  },
  'ML-DSA44': {
    opts: getOpts(ml_dsa44),
    noble: getNoble(ml_dsa44),
  },
  'ML-DSA65': {
    opts: getOpts(ml_dsa65),
    noble: getNoble(ml_dsa65),
  },
  'ML-DSA87': {
    opts: getOpts(ml_dsa87),
    noble: getNoble(ml_dsa87),
  },
};
const FNS = ['keygen', 'sign', 'verify'];

const SAMPLES = 100;
export async function main() {
  const onlyNoble = process.argv[2] === 'noble';
  if (onlyNoble) {
    for (const fn of FNS) {
      await compare(
        `==== ${fn} ====`,
        SAMPLES,
        Object.fromEntries(
          Object.entries(DILITHIUM).map(([k, v]) => [k, v.noble[fn].bind(null, v.opts)])
        )
      );
    }
    return;
  }
  await initDashline();

  for (const [algoName, libraries] of Object.entries(DILITHIUM)) {
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
