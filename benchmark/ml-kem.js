import { compare } from 'micro-bmark';
import { deepStrictEqual } from 'node:assert';
import { ml_kem1024, ml_kem512, ml_kem768 } from '../ml-kem.js';

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

const MLKEM = {
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

const SAMPLES = 5_000;
export async function main() {
  const onlyNoble = process.argv[2] === 'noble';
  if (onlyNoble) {
    for (const fn of FNS) {
      await compare(
        `==== ${fn} ====`,
        SAMPLES,
        Object.fromEntries(
          Object.entries(MLKEM).map(([k, v]) => [k, v.noble[fn].bind(null, v.opts)])
        )
      );
    }
    return;
  }
  // await initDashline();
  for (const [algoName, libraries] of Object.entries(MLKEM)) {
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
}

// ESM is broken.
import url from 'node:url';
if (import.meta.url === url.pathToFileURL(process.argv[1]).href) {
  main();
}
