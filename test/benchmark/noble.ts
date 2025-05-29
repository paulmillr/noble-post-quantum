import mark from 'micro-bmark';
import { ml_dsa65 } from '../../src/ml-dsa.ts';
import { ml_kem768 } from '../../src/ml-kem.ts';
import * as slh from '../../src/slh-dsa.ts';
import { randomBytes } from '../../src/utils.ts';

function mlKemOpts(lib) {
  const { publicKey, secretKey } = lib.keygen();
  const { cipherText, sharedSecret } = lib.encapsulate(publicKey);
  return { publicKey, secretKey, cipherText, sharedSecret };
}

function mlDsaOpts(lib) {
  const seed = randomBytes(32);
  const msg = randomBytes(32);
  const { publicKey, secretKey } = lib.keygen(seed);
  const signature = lib.sign(secretKey, msg);
  return { seed, msg, publicKey, secretKey, signature };
}

function slhDsaOpts(lib) {
  const { publicKey, secretKey } = lib.keygen();
  const msg = randomBytes(32);
  const signature = lib.sign(secretKey, msg);
  return { msg, publicKey, secretKey, signature };
}

(async () => {
  console.log('# ML-KEM768');
  const mlkem = ml_kem768;
  const mlkemo = mlKemOpts(mlkem);
  await mark('keygen', () => mlkem.keygen());
  await mark('encapsulate', () => mlkem.encapsulate(mlkemo.publicKey));
  await mark('decapsulate', () => mlkem.decapsulate(mlkemo.cipherText, mlkemo.secretKey));

  console.log('# ML-DSA65');
  const mldsa = ml_dsa65;
  const mldsao = mlDsaOpts(mldsa);
  await mark('keygen', () => mldsa.keygen(randomBytes(32)));
  await mark('sign', () => mldsa.sign(mldsao.secretKey, mldsao.msg));
  await mark('verify', () => mldsa.verify(mldsao.publicKey, mldsao.msg, mldsao.signature));

  console.log('# SLH-DSA SHA2 192f');
  const slhdsa = slh.slh_dsa_sha2_192f;
  const slhdsao = slhDsaOpts(slhdsa);
  await mark('keygen', () => slhdsa.keygen(randomBytes(72)));
  await mark('sign', () => slhdsa.sign(slhdsao.secretKey, slhdsao.msg));
  await mark('verify', () => slhdsa.verify(slhdsao.publicKey, slhdsao.msg, slhdsao.signature));
})();
