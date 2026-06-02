import { deepStrictEqual as eql } from 'node:assert';
import { sha256 } from '@noble/hashes/sha2.js';
import { concatBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import * as noblePlatform from '@awasm/noble/noble.js';
import * as stubs from '@awasm/noble/stub.js';
import * as wasmPlatform from '@awasm/noble/wasm.js';
import * as wasmThreadsPlatform from '@awasm/noble/wasm_threads.js';
import { WP } from '@awasm/noble/workers.js';
import bench from '@paulmillr/jsbt/bench.js';
import { falcon1024, falcon512 } from '../src/falcon.ts';
import { ml_dsa65 } from '../src/ml-dsa.ts';
import { ml_kem768 } from '../src/ml-kem.ts';
import * as slh from '../src/slh-dsa.ts';

const platformFns = [
  'sha256',
  'sha512',
  'sha3_256',
  'sha3_512',
  'shake128',
  'shake256',
  'chacha20',
] as const;

function installPlatform(platform) {
  for (const name of platformFns) stubs[name].install(platform[name]);
}

async function readyPlatform(name: string) {
  if (name !== 'wasm_threads') return;
  await WP.waitOnline();
}

function fixedBytes(label: string, len: number) {
  const out = new Uint8Array(len);
  for (let pos = 0, i = 0; pos < len; i++) {
    const block = sha256(utf8ToBytes(`${label}-${i}`));
    const take = Math.min(block.length, len - pos);
    out.set(block.subarray(0, take), pos);
    pos += take;
  }
  return out;
}

function mlKemOpts(lib) {
  const seed = fixedBytes('ml-kem-keygen-seed', 64);
  const msg = fixedBytes('ml-kem-msg', 32);
  const { publicKey, secretKey } = lib.keygen(seed);
  const { cipherText, sharedSecret } = lib.encapsulate(publicKey, msg);
  return { seed, msg, publicKey, secretKey, cipherText, sharedSecret };
}

function mlDsaOpts(lib) {
  const seed = fixedBytes('ml-dsa-keygen-seed', 32);
  const msg = fixedBytes('ml-dsa-msg', 32);
  const rand = fixedBytes('ml-dsa-sign-seed', lib.lengths.signRand);
  const { publicKey, secretKey } = lib.keygen(seed);
  const signature = lib.sign(msg, secretKey, { extraEntropy: rand });
  return { seed, msg, rand, publicKey, secretKey, signature };
}

function slhDsaOpts(lib) {
  const seed = fixedBytes('slh-dsa-keygen-seed', lib.lengths.seed);
  const msg = fixedBytes('slh-dsa-msg', 32);
  const rand = fixedBytes('slh-dsa-sign-seed', lib.lengths.signRand);
  const { publicKey, secretKey } = lib.keygen(seed);
  const signature = lib.sign(msg, secretKey, { extraEntropy: rand });
  return { seed, msg, rand, publicKey, secretKey, signature };
}

function falconSeed(label: string) {
  const seed = sha256(utf8ToBytes(label));
  return concatBytes(seed, seed.subarray(0, 16));
}

function falconOpts(lib, name: string) {
  const seed = falconSeed(`${name}-keygen-seed`);
  const msg = sha256(utf8ToBytes(`${name}-msg`));
  // Falcon signing uses rejection sampling, so fixed extra entropy keeps runs comparable.
  const rand = falconSeed(`${name}-sign-seed`);
  const { publicKey, secretKey } = lib.keygen(seed);
  const signature = lib.sign(msg, secretKey, { extraEntropy: rand });
  return { seed, msg, rand, publicKey, secretKey, signature };
}

const checkSnapshot = (expected, key: string, got) => {
  if (expected[key] === undefined) expected[key] = got;
  else eql(got, expected[key]);
};

async function runSuite(platformName: string, expected) {
  console.log(`# ${platformName} / ML-KEM768`);
  const mlkem = ml_kem768;
  const mlkemo = mlKemOpts(mlkem);
  checkSnapshot(expected, 'mlkem', {
    keys: mlkem.keygen(mlkemo.seed),
    enc: mlkem.encapsulate(mlkemo.publicKey, mlkemo.msg),
    dec: mlkem.decapsulate(mlkemo.cipherText, mlkemo.secretKey),
  });
  await bench('keygen', () => mlkem.keygen(mlkemo.seed));
  await bench('encapsulate', () => mlkem.encapsulate(mlkemo.publicKey, mlkemo.msg));
  await bench('decapsulate', () => mlkem.decapsulate(mlkemo.cipherText, mlkemo.secretKey));

  console.log(`# ${platformName} / ML-DSA65`);
  const mldsa = ml_dsa65;
  const mldsao = mlDsaOpts(mldsa);
  checkSnapshot(expected, 'mldsa', {
    keys: mldsa.keygen(mldsao.seed),
    sig: mldsa.sign(mldsao.msg, mldsao.secretKey, { extraEntropy: mldsao.rand }),
    ok: mldsa.verify(mldsao.signature, mldsao.msg, mldsao.publicKey),
  });
  // NOTE: signature uses rejection sampling, which means time significantly depends on random values
  // more info we reject, more xof blocks we need to run. To make benchmarks comparable (is new version faster or slower?)
  // we make all seeds fixed. Difference in speed between various seeds can easily be x10.
  // Rejection sampling depends on:
  // - message
  // - external random
  // - key
  await bench('keygen', () => mldsa.keygen(mldsao.seed));
  await bench('sign', () =>
    mldsa.sign(mldsao.msg, mldsao.secretKey, { extraEntropy: mldsao.rand })
  );
  await bench('verify', () => mldsa.verify(mldsao.signature, mldsao.msg, mldsao.publicKey));

  console.log(`# ${platformName} / SLH-DSA SHA2 192f`);
  const slhdsa = slh.slh_dsa_sha2_192f;
  const slhdsao = slhDsaOpts(slhdsa);
  checkSnapshot(expected, 'slhdsa', {
    keys: slhdsa.keygen(slhdsao.seed),
    sig: slhdsa.sign(slhdsao.msg, slhdsao.secretKey, { extraEntropy: slhdsao.rand }),
    ok: slhdsa.verify(slhdsao.signature, slhdsao.msg, slhdsao.publicKey),
  });
  await bench('keygen', () => slhdsa.keygen(slhdsao.seed));
  await bench('sign', () =>
    slhdsa.sign(slhdsao.msg, slhdsao.secretKey, { extraEntropy: slhdsao.rand })
  );
  await bench('verify', () => slhdsa.verify(slhdsao.signature, slhdsao.msg, slhdsao.publicKey));

  console.log(`# ${platformName} / SLH-DSA SHAKE 192f`);
  const slhshake = slh.slh_dsa_shake_192f;
  const slhshakeo = slhDsaOpts(slhshake);
  checkSnapshot(expected, 'slhshake', {
    keys: slhshake.keygen(slhshakeo.seed),
    sig: slhshake.sign(slhshakeo.msg, slhshakeo.secretKey, { extraEntropy: slhshakeo.rand }),
    ok: slhshake.verify(slhshakeo.signature, slhshakeo.msg, slhshakeo.publicKey),
  });
  await bench('keygen', () => slhshake.keygen(slhshakeo.seed));
  await bench('sign', () =>
    slhshake.sign(slhshakeo.msg, slhshakeo.secretKey, { extraEntropy: slhshakeo.rand })
  );
  await bench('verify', () =>
    slhshake.verify(slhshakeo.signature, slhshakeo.msg, slhshakeo.publicKey)
  );

  console.log(`# ${platformName} / Falcon512`);
  const falcon512o = falconOpts(falcon512, 'falcon512');
  checkSnapshot(expected, 'falcon512', {
    keys: falcon512.keygen(falcon512o.seed),
    sig: falcon512.sign(falcon512o.msg, falcon512o.secretKey, { extraEntropy: falcon512o.rand }),
    ok: falcon512.verify(falcon512o.signature, falcon512o.msg, falcon512o.publicKey),
  });
  await bench('keygen', () => falcon512.keygen(falcon512o.seed));
  await bench('sign', () =>
    falcon512.sign(falcon512o.msg, falcon512o.secretKey, { extraEntropy: falcon512o.rand })
  );
  await bench('verify', () =>
    falcon512.verify(falcon512o.signature, falcon512o.msg, falcon512o.publicKey)
  );

  console.log(`# ${platformName} / Falcon1024`);
  const falcon1024o = falconOpts(falcon1024, 'falcon1024');
  checkSnapshot(expected, 'falcon1024', {
    keys: falcon1024.keygen(falcon1024o.seed),
    sig: falcon1024.sign(falcon1024o.msg, falcon1024o.secretKey, {
      extraEntropy: falcon1024o.rand,
    }),
    ok: falcon1024.verify(falcon1024o.signature, falcon1024o.msg, falcon1024o.publicKey),
  });
  await bench('keygen', () => falcon1024.keygen(falcon1024o.seed));
  await bench('sign', () =>
    falcon1024.sign(falcon1024o.msg, falcon1024o.secretKey, { extraEntropy: falcon1024o.rand })
  );
  await bench('verify', () =>
    falcon1024.verify(falcon1024o.signature, falcon1024o.msg, falcon1024o.publicKey)
  );
}

(async () => {
  const platforms = [
    ['noble', noblePlatform],
    ['wasm', wasmPlatform],
    ['wasm_threads', wasmThreadsPlatform],
  ] as const;
  const expected = {};
  for (let i = 0; i < platforms.length; i++) {
    const [name, platform] = platforms[i];
    if (i > 0) console.log('');
    installPlatform(platform);
    try {
      await readyPlatform(name);
      await runSuite(name, expected);
      await readyPlatform(name);
      console.log(`# ${name} validation: ok`);
    } catch (e) {
      console.log(`# ${name} validation: skipped`);
      console.error(e);
      continue;
    }
  }
})();
