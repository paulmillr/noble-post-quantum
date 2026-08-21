import { describe, it } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql } from 'node:assert';
import {
  ml_kem1024 as noble1024,
  ml_kem512 as noble512,
  ml_kem768 as noble768,
} from '../src/ml-kem.ts';
import { ml_kem768_x25519 as nobleX25519 } from '../src/hybrid.ts';
import {
  ml_kem1024 as web1024,
  ml_kem512 as web512,
  ml_kem768 as web768,
  ml_kem768_x25519 as webX25519,
} from '../src/webcrypto.ts';

const KEMS = [
  { name: 'ML-KEM-512', noble: noble512, web: web512 },
  { name: 'ML-KEM-768', noble: noble768, web: web768 },
  { name: 'ML-KEM-1024', noble: noble1024, web: web1024 },
  { name: 'MLKEM768-X25519', noble: nobleX25519, web: webX25519 },
];
// `it()` registration is synchronous, so support has to be probed up front. The wrappers memoize,
// so the tests below re-use these results instead of paying for a second round-trip.
const supported = await Promise.all(KEMS.map(({ web }) => web.isSupported()));

describe('WebCrypto', () => {
  it('lengths match the synchronous implementations', () => {
    for (const { name, noble, web } of KEMS) {
      eql(web.webCryptoName, name);
      // `secretKey` is deliberately excluded: the wrappers report the seed length, while ML-KEM's
      // synchronous `lengths.secretKey` is the much larger expanded decapsulation key.
      eql(web.lengths.seed, noble.lengths.seed);
      eql(web.lengths.publicKey, noble.lengths.publicKey);
      eql(web.lengths.cipherText, noble.lengths.cipherText);
    }
  });

  KEMS.forEach(({ name, noble, web }, i) => {
    (supported[i] ? it : it.skip)(name, async () => {
      const generated = await web.keygen();
      eql(generated.secretKey.length, web.lengths.secretKey);
      eql(generated.publicKey.length, web.lengths.publicKey);
      eql(await web.getPublicKey(generated.secretKey), generated.publicKey);
      eql(noble.keygen(generated.secretKey).publicKey, generated.publicKey);
      const encapsulated = await web.encapsulate(generated.publicKey);
      eql(encapsulated.cipherText.length, web.lengths.cipherText);
      eql(encapsulated.sharedSecret.length, 32);
      eql(
        await web.decapsulate(encapsulated.cipherText, generated.secretKey),
        encapsulated.sharedSecret
      );

      const seed = Uint8Array.from({ length: web.lengths.seed }, (_, i) => i + 1);
      const webKeys = await web.keygen(seed);
      const nobleKeys = noble.keygen(seed);
      eql(webKeys.secretKey, seed);
      eql(webKeys.publicKey, nobleKeys.publicKey);
      eql(await web.getPublicKey(webKeys.secretKey), nobleKeys.publicKey);

      const webEncapsulated = await web.encapsulate(webKeys.publicKey);
      eql(
        noble.decapsulate(webEncapsulated.cipherText, nobleKeys.secretKey),
        webEncapsulated.sharedSecret
      );
      const nobleEncapsulated = noble.encapsulate(
        nobleKeys.publicKey,
        new Uint8Array(noble.lengths.msgRand).fill(7)
      );
      eql(
        await web.decapsulate(nobleEncapsulated.cipherText, webKeys.secretKey),
        nobleEncapsulated.sharedSecret
      );
    });
  });
});

it.runWhen(import.meta.url);
