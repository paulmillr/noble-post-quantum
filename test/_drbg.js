import { concatBytes } from '@noble/ciphers/utils';
import { ecb } from '@noble/ciphers/aes';
import { bytes as abytes } from '@noble/hashes/_assert';

// Small DRBG for tests.
// TODO:
// - we can move to tests as is
// - or add more tests && verify with spec to make it usable outside kyber tests
export const aes256_ctr_drbg = (seed, personalization) => {
  const seedLength = 48;
  abytes(seed, 48);
  const reseedInterval = 2 ** seedLength;
  const key = new Uint8Array(32);
  const V = new Uint8Array(16);
  let reseedCounter = 0;
  const incrementCounter = () => {
    let carry = 1;
    for (let i = V.length - 1; i >= 0; i--) {
      carry = (carry + (V[i] & 0xff)) | 0;
      V[i] = carry & 0xff;
      carry >>>= 8;
    }
  };
  const update = (data) => {
    const tmp = new Uint8Array(seedLength);
    const c = ecb(key, { disablePadding: true });
    for (let i = 0; i < seedLength / ecb.blockSize; i++) {
      incrementCounter();
      tmp.set(c.encrypt(V), i * ecb.blockSize);
    }
    for (let i = 0; i < tmp.length; i++) tmp[i] ^= data[i];
    key.set(tmp.subarray(0, 32));
    V.set(tmp.subarray(32));
  };
  const reseed = (data) => {
    update(data);
    reseedCounter += 1;
  };
  const pad = (data) => {
    abytes(data);
    if (data.length > seedLength) {
      throw new Error(
        `aes256_ctr_drbg: data (len=${data.length}) should be less than ${seedLength}`
      );
    } else if (data.length === seedLength) return data;
    return concatBytes(data, new Uint8Array(seedLength - data.length));
  };

  if (personalization) {
    const _seed = seed.slice();
    personalization = pad(personalization);
    for (let i = 0; i < _seed.length; i++) _seed[i] ^= personalization[i];
    reseed(_seed);
  } else reseed(seed);

  return (len, entropy) => {
    if (reseedCounter >= reseedInterval)
      throw new Error('aes256_ctr_drbg: exhausted, need to reseed');
    if (entropy) {
      entropy = pad(entropy);
      update(entropy);
    } else entropy = new Uint8Array(seedLength);
    const out = new Uint8Array(ecb.blockSize * Math.ceil(len / ecb.blockSize));
    const c = ecb(key, { disablePadding: true });
    for (let i = 0; i < out.length; i += ecb.blockSize) {
      incrementCounter();
      out.set(c.encrypt(V), i);
    }
    reseed(entropy);
    return out.subarray(0, len);
  };
};
