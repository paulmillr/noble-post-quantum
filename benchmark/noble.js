import { ml_kem512, ml_kem768, ml_kem1024 } from '@noble/post-quantum/ml-kem';
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa';
import * as slh from '@noble/post-quantum/slh-dsa';
import { randomBytes } from '@noble/post-quantum/utils';
import { mark } from 'micro-bmark';

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
  await mark('keygen', 3000, () => mlkem.keygen());
  await mark('encapsulate', 3000, () => mlkem.encapsulate(mlkemo.publicKey));
  await mark('decapsulate', 3000, () => mlkem.decapsulate(mlkemo.cipherText, mlkemo.secretKey));

  console.log('# ML-DSA65');
  const mldsa = ml_dsa65;
  const mldsao = mlDsaOpts(mldsa);
  await mark('keygen', 1000, () => mldsa.keygen(randomBytes(32)));
  await mark('sign', 300, () => mldsa.sign(mldsao.secretKey, mldsao.msg));
  await mark('verify', 500, () => mldsa.verify(mldsao.publicKey, mldsao.msg, mldsao.signature));

  console.log('# SLH-DSA SHA2 192f');
  const slhdsa = slh.slh_dsa_sha2_192f;
  const slhdsao = slhDsaOpts(slhdsa);
  await mark('keygen', 1000, () => slhdsa.keygen(randomBytes(72)));
  await mark('sign', 10, () => slhdsa.sign(slhdsao.secretKey, slhdsao.msg));
  await mark('verify', 200, () => slhdsa.verify(slhdsao.publicKey, slhdsao.msg, slhdsao.signature));
})();
