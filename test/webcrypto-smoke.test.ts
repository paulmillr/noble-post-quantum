import test from 'node:test';
import assert from 'node:assert';
import { webcrypto } from 'node:crypto';

test('WebCrypto ML-KEM-768 is fully enabled and functional in Node.js', async (t) => {
  await t.test('1. Ensure SubtleCrypto is available', async () => {
    assert.ok(webcrypto, 'webcrypto should be available');
    assert.ok(webcrypto.subtle, 'webcrypto.subtle should be defined');
  });

  let kp: any;
  let pqcCiphertext: ArrayBuffer;
  let pqcSharedKey: ArrayBuffer;

  await t.test('2. Generate ML-KEM-768 KeyPair', async () => {
    try {
      kp = await webcrypto.subtle.generateKey({ name: 'ML-KEM-768' }, true, [
        'encapsulateBits',
        'decapsulateBits',
      ] as any);
      assert.strictEqual(kp.publicKey.algorithm.name, 'ML-KEM-768');
      assert.strictEqual(kp.privateKey.algorithm.name, 'ML-KEM-768');
    } catch (e: any) {
      assert.fail(`Key generation failed: ${e.message}`);
    }
  });

  await t.test('3. Encapsulate a shared secret against the Public Key', async () => {
    try {
      const subtleAny = webcrypto.subtle as any;
      const result = await subtleAny.encapsulateBits({ name: 'ML-KEM-768' }, kp.publicKey);

      pqcSharedKey = result.sharedKey;
      pqcCiphertext = result.ciphertext;

      assert.strictEqual(pqcSharedKey.byteLength, 32);
      assert.strictEqual(pqcCiphertext.byteLength, 1088);
    } catch (e: any) {
      assert.fail(`Encapsulation failed: ${e.message}`);
    }
  });

  await t.test('4. Decapsulate the ciphertext using the Private Key', async () => {
    try {
      const subtleAny = webcrypto.subtle as any;
      const decapsulatedKey = await subtleAny.decapsulateBits(
        { name: 'ML-KEM-768' },
        kp.privateKey,
        pqcCiphertext
      );

      const originalBytes = new Uint8Array(pqcSharedKey);
      const decapsulatedBytes = new Uint8Array(decapsulatedKey);

      assert.strictEqual(originalBytes.length, decapsulatedBytes.length);
      for (let i = 0; i < originalBytes.length; i++) {
        assert.strictEqual(originalBytes[i], decapsulatedBytes[i]);
      }
    } catch (e: any) {
      assert.fail(`Decapsulation failed: ${e.message}`);
    }
  });
});
