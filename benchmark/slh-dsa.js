import { deepStrictEqual } from 'node:assert';
import { compare, utils } from 'micro-bmark';
import * as dsa from '../slh-dsa.js';

const msg = new Uint8Array(32).fill(2);

const getOpts = (lib) => {
  const { publicKey, secretKey } = lib.keygen();
  const signature = lib.sign(secretKey, msg, new Uint8Array(lib.signRandBytes));
  return { publicKey, secretKey, signature };
};

const getNoble = (lib) => ({
  keygen: () => lib.keygen(),
  sign: (opts) =>
    deepStrictEqual(
      lib.sign(opts.secretKey, msg, new Uint8Array(lib.signRandBytes)),
      opts.signature,
      'sig'
    ),
  verify: (opts) => deepStrictEqual(lib.verify(opts.publicKey, msg, opts.signature), true),
});

const testNoble = (lib) => ({ opts: getOpts(lib), noble: getNoble(lib) });

const SLHDSA = {
  slh_dsa_sha2_128f: testNoble(dsa.slh_dsa_sha2_128f),
  slh_dsa_sha2_192f: testNoble(dsa.slh_dsa_sha2_192f),
  slh_dsa_sha2_256f: testNoble(dsa.slh_dsa_sha2_256f),

  slh_dsa_shake_128f: testNoble(dsa.slh_dsa_shake_128f),
  slh_dsa_shake_192f: testNoble(dsa.slh_dsa_shake_192f),
  slh_dsa_shake_256f: testNoble(dsa.slh_dsa_shake_256f),

  // Too slow
  // slh_dsa_shake_128s: testNoble(dsa.slh_dsa_shake_128s),
  // slh_dsa_shake_192s: testNoble(dsa.slh_dsa_shake_192s),
  // slh_dsa_shake_256s: testNoble(dsa.slh_dsa_shake_256s),
  slh_dsa_sha2_128s: testNoble(dsa.slh_dsa_sha2_128s),
  slh_dsa_sha2_192s: testNoble(dsa.slh_dsa_sha2_192s),
  slh_dsa_sha2_256s: testNoble(dsa.slh_dsa_sha2_256s),
};
const FNS = ['keygen', 'sign', 'verify'];

const SAMPLES = 10;
export async function main() {
  const onlyNoble = process.argv[2] === 'noble';
  if (onlyNoble) {
    for (const fn of FNS) {
      await compare(
        `==== ${fn} ====`,
        SAMPLES,
        Object.fromEntries(
          Object.entries(SLHDSA).map(([k, v]) => [k, v.noble[fn].bind(null, v.opts)])
        )
      );
    }
    return;
  }
  for (const [algoName, libraries] of Object.entries(SLHDSA)) {
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
import url from 'node:url';
if (import.meta.url === url.pathToFileURL(process.argv[1]).href) {
  main();
}
