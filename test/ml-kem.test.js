import { deepStrictEqual, notDeepStrictEqual, throws } from 'node:assert';
import { pathToFileURL } from 'node:url';
import { describe, should } from 'micro-should';
import { ml_kem512, ml_kem768, ml_kem1024 } from '../ml-kem.js';
import { __dirname } from './util.js';

describe('ML-KEM Kyber', () => {
  should('Example', () => {
    // Alice generates keys
    const aliceKeys = ml_kem1024.keygen(); // [Alice] generates key pair (secret and public key)
    const alicePub = aliceKeys.publicKey; // [Alice] sends public key to Bob (somehow)
    // aliceKeys.secretKey never leaves [Alice] system and unknown to other parties

    // Bob creates cipherText for Alice
    // [Bob] generates shared secret for Alice publicKey
    const { cipherText, sharedSecret: bobShared } = ml_kem1024.encapsulate(alicePub);
    // bobShared never leaves [Bob] system and unknown to other parties

    // Alice gets cipherText from Bob
    // [Alice] decrypts sharedSecret from Bob
    const aliceShared = ml_kem1024.decapsulate(cipherText, aliceKeys.secretKey);

    // Now, both Alice and Both have same sharedSecret key without exchanging in plainText
    deepStrictEqual(aliceShared, bobShared);

    // Warning: Can be MITM-ed
    const carolKeys = ml_kem1024.keygen();
    const carolShared = ml_kem1024.decapsulate(cipherText, carolKeys.secretKey); // No error!
    notDeepStrictEqual(aliceShared, carolShared); // Different key!
  });
});

// ESM is broken.
if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  should.run();
}
