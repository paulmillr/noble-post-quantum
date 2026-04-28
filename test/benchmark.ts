import { deepStrictEqual } from 'node:assert';
import { sha256 } from '@awasm/noble';
import { concatBytes, utf8ToBytes } from '@awasm/noble/utils.js';
import bench from '@paulmillr/jsbt/bench.js';
import { falcon1024, falcon512 } from '../src/falcon.ts';
import { ml_dsa65 } from '../src/ml-dsa.ts';
import { ml_kem768 } from '../src/ml-kem.ts';
import * as slh from '../src/slh-dsa.ts';
import { randomBytes } from '../src/utils.ts';

function mlKemOpts(lib) {
  const { publicKey, secretKey } = lib.keygen();
  const { cipherText, sharedSecret } = lib.encapsulate(publicKey);
  return { publicKey, secretKey, cipherText, sharedSecret };
}

function mlDsaOpts(lib) {
  const seed = sha256(utf8ToBytes('ml-dsa-keygen-seed'));
  const msg = sha256(utf8ToBytes('ml-dsa-msg'));
  const { publicKey, secretKey } = lib.keygen(seed);
  const signature = lib.sign(msg, secretKey);
  return { seed, msg, publicKey, secretKey, signature };
}

function slhDsaOpts(lib) {
  const { publicKey, secretKey } = lib.keygen();
  const msg = randomBytes(32);
  const signature = lib.sign(msg, secretKey);
  return { msg, publicKey, secretKey, signature };
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
  return { msg, rand, publicKey, secretKey, signature };
}

(async () => {
  console.log('# ML-KEM768');
  const mlkem = ml_kem768;
  const mlkemo = mlKemOpts(mlkem);
  await bench('keygen', () => mlkem.keygen());
  await bench('encapsulate', () => mlkem.encapsulate(mlkemo.publicKey));
  await bench('decapsulate', () => mlkem.decapsulate(mlkemo.cipherText, mlkemo.secretKey));

  console.log('# ML-DSA65');
  const mldsa = ml_dsa65;
  const mldsao = mlDsaOpts(mldsa);
  // NOTE: signature uses rejection sampling, which means time significantly depends on random values
  // more info we reject, more xof blocks we need to run. To make benchmarks comparable (is new version faster or slower?)
  // we make all seeds fixed. Difference in speed between various seeds can easily be x10.
  // Rejection sampling depends on:
  // - message
  // - external random
  // - key
  const rand = sha256(utf8ToBytes('noble-post-quantum'));
  await bench('keygen', () => mldsa.keygen(randomBytes(32)));
  await bench('sign', () => mldsa.sign(mldsao.msg, mldsao.secretKey, { extraEntropy: rand }));
  await bench('verify', () => mldsa.verify(mldsao.signature, mldsao.msg, mldsao.publicKey));

  console.log('# SLH-DSA SHA2 192f');
  const slhdsa = slh.slh_dsa_sha2_192f;
  const slhdsao = slhDsaOpts(slhdsa);
  await bench('keygen', () => slhdsa.keygen(randomBytes(72)));
  await bench('sign', () => slhdsa.sign(slhdsao.msg, slhdsao.secretKey));
  await bench('verify', () => slhdsa.verify(slhdsao.signature, slhdsao.msg, slhdsao.publicKey));

  console.log('# Falcon512');
  const falcon512o = falconOpts(falcon512, 'falcon512');
  deepStrictEqual(
    falcon512.verify(falcon512o.signature, falcon512o.msg, falcon512o.publicKey),
    true
  );
  await bench('keygen', () => falcon512.keygen(randomBytes(48)));
  await bench('sign', () =>
    falcon512.sign(falcon512o.msg, falcon512o.secretKey, { extraEntropy: falcon512o.rand })
  );
  await bench('verify', () =>
    falcon512.verify(falcon512o.signature, falcon512o.msg, falcon512o.publicKey)
  );

  console.log('# Falcon1024');
  const falcon1024o = falconOpts(falcon1024, 'falcon1024');
  deepStrictEqual(
    falcon1024.verify(falcon1024o.signature, falcon1024o.msg, falcon1024o.publicKey),
    true
  );
  await bench('keygen', () => falcon1024.keygen(randomBytes(48)));
  await bench('sign', () =>
    falcon1024.sign(falcon1024o.msg, falcon1024o.secretKey, { extraEntropy: falcon1024o.rand })
  );
  await bench('verify', () =>
    falcon1024.verify(falcon1024o.signature, falcon1024o.msg, falcon1024o.publicKey)
  );
})();
