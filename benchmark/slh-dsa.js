import { deepStrictEqual } from 'node:assert';
import { compare, utils } from 'micro-bmark';
import * as sphincs_sha2 from '../slh-dsa.js';
import * as sphincs_shake from '../slh-dsa.js';
// wasm
// import { default as wasmSphincs } from 'sphincs';

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

const SPHINCS = {
  // Fast
  sphincs_sha2_128f_simple: testNoble(sphincs_sha2.sphincs_sha2_128f_simple),
  sphincs_sha2_192f_simple: testNoble(sphincs_sha2.sphincs_sha2_192f_simple),
  sphincs_sha2_256f_simple: testNoble(sphincs_sha2.sphincs_sha2_256f_simple),
  // sphincs_sha2_128f_robust: testNoble(sphincs_sha2.sphincs_sha2_128f_robust),

  // s version is too slow for now
  // sphincs_sha2_128s_simple: testNoble(sphincs.sphincs_sha2_128s_simple),
  // sphincs_sha2_128s_robust: testNoble(sphincs.sphincs_sha2_128s_robust),

  sphincs_shake_128f_simple: testNoble(sphincs_shake.sphincs_shake_128f_simple),
  sphincs_shake_192f_simple: testNoble(sphincs_shake.sphincs_shake_192f_simple),
  sphincs_shake_256f_simple: testNoble(sphincs_shake.sphincs_shake_256f_simple),

  //sphincs_shake_128f_robust: testNoble(sphincs_shake.sphincs_shake_128f_robust),

  // Worst case:
  //sphincs_sha2_256s_robust: testNoble(sphincs.sphincs_sha2_256s_robust),
  //sphincs_shake_256s_robust: testNoble(sphincs.sphincs_shake_256s_robust),

  // sphincs_shake_256s_robust: {
  //   opts: getOpts(sphincs.sphincs_shake_256s_robust),
  //   // The default parameter set is SPHINCS+-SHAKE-256s-robust (roughly 256-bit strength).
  //   wasm: {
  //     keygen: async () => await wasmSphincs.keyPair(),
  //     // Cannot provide random & verify
  //     // Also, seems like different version of sphincs. Awesome.
  //     sign: async (opts) => await wasmSphincs.signDetached(msg, opts.secretKey),
  //     verify: async (opts) =>
  //       deepStrictEqual(
  //         await wasmSphincs.verifyDetached(opts.signature, msg, opts.publicKey),
  //         true
  //       ),
  //   },
  //   noble: getNoble(sphincs.sphincs_shake_256s_robust),
  // },
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
          Object.entries(SPHINCS).map(([k, v]) => [k, v.noble[fn].bind(null, v.opts)])
        )
      );
    }
    return;
  }
  for (const [algoName, libraries] of Object.entries(SPHINCS)) {
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
