import { describe, it } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql, rejects } from 'node:assert';
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

async function withSubtle<T>(subtle: any, run: () => Promise<T>): Promise<T> {
  const previous = Object.getOwnPropertyDescriptor(globalThis, 'crypto');
  Object.defineProperty(globalThis, 'crypto', {
    configurable: true,
    value: { subtle },
  });
  try {
    return await run();
  } finally {
    if (previous === undefined) delete (globalThis as any).crypto;
    else Object.defineProperty(globalThis, 'crypto', previous);
  }
}

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

  it('rejects and wipes malformed provider encapsulation outputs', async () => {
    let ciphertext: unknown = new ArrayBuffer(web512.lengths.cipherText);
    let sharedKey: unknown = new ArrayBuffer(32);
    const subtle = {
      importKey: async () => ({}),
      encapsulateBits: async () => ({ ciphertext, sharedKey }),
    };
    await withSubtle(subtle, async () => {
      const publicKey = new Uint8Array(web512.lengths.publicKey);
      for (const length of [0, web512.lengths.cipherText - 1, web512.lengths.cipherText + 1]) {
        ciphertext = new ArrayBuffer(length);
        sharedKey = new ArrayBuffer(32);
        const secretView = new Uint8Array(sharedKey).fill(0xa5);
        await rejects(web512.encapsulate(publicKey), /cipherText/);
        eql(secretView, new Uint8Array(32));
      }
      for (const malformed of [web512.lengths.cipherText, { length: web512.lengths.cipherText }]) {
        ciphertext = malformed;
        sharedKey = new ArrayBuffer(32);
        const secretView = new Uint8Array(sharedKey).fill(0xa5);
        await rejects(web512.encapsulate(publicKey), /ciphertext.*ArrayBuffer/);
        eql(secretView, new Uint8Array(32));
      }
      for (const length of [0, 31, 33]) {
        ciphertext = new ArrayBuffer(web512.lengths.cipherText);
        sharedKey = new ArrayBuffer(length);
        const secretView = new Uint8Array(sharedKey).fill(0xa5);
        await rejects(web512.encapsulate(publicKey), /sharedSecret/);
        eql(secretView, new Uint8Array(length));
      }
      for (const malformed of [32, { length: 32 }]) {
        ciphertext = new ArrayBuffer(web512.lengths.cipherText);
        sharedKey = malformed;
        await rejects(web512.encapsulate(publicKey), /sharedKey.*ArrayBuffer/);
      }
    });
  });

  it('rejects and wipes malformed provider decapsulation outputs', async () => {
    let sharedKey: unknown = new ArrayBuffer(32);
    const subtle = {
      importKey: async () => ({}),
      decapsulateBits: async () => sharedKey,
    };
    await withSubtle(subtle, async () => {
      const cipherText = new Uint8Array(web512.lengths.cipherText);
      const secretKey = new Uint8Array(web512.lengths.secretKey);
      for (const length of [0, 31, 33]) {
        sharedKey = new ArrayBuffer(length);
        const secretView = new Uint8Array(sharedKey).fill(0xa5);
        await rejects(web512.decapsulate(cipherText, secretKey), /sharedSecret/);
        eql(secretView, new Uint8Array(length));
      }
      for (const malformed of [32, { length: 32 }]) {
        sharedKey = malformed;
        await rejects(web512.decapsulate(cipherText, secretKey), /sharedKey.*ArrayBuffer/);
      }
    });
  });

  it('support probe rejects truncated secrets, cleans up, and memoizes failure', async () => {
    let calls = 0;
    let exportedSeed: Uint8Array | undefined;
    let providerSecret: Uint8Array | undefined;
    const subtle = {
      generateKey: async () => {
        calls++;
        return { privateKey: {}, publicKey: {} };
      },
      exportKey: async (format: string) => {
        calls++;
        const bytes = new Uint8Array(format === 'raw-seed' ? 64 : 800).fill(0x5a);
        if (format === 'raw-seed') exportedSeed = bytes;
        return bytes.buffer;
      },
      importKey: async () => {
        calls++;
        return {};
      },
      getPublicKey: async () => {
        calls++;
        return {};
      },
      encapsulateBits: async () => {
        calls++;
        providerSecret = new Uint8Array(31).fill(0xa5);
        return {
          ciphertext: new ArrayBuffer(768),
          sharedKey: providerSecret.buffer,
        };
      },
      decapsulateBits: async () => {
        calls++;
        return new Uint8Array(31).fill(0xa5).buffer;
      },
    };
    await withSubtle(subtle, async () => {
      // A cache-busted module has a fresh per-wrapper support memo, independent of the real-runtime
      // probes performed at module initialization above.
      const freshPath = '../src/webcrypto.ts?malformed-support-probe';
      const fresh = await import(freshPath);
      eql(await fresh.ml_kem512.isSupported(), false);
      if (exportedSeed === undefined || providerSecret === undefined)
        throw new Error('expected malformed provider outputs');
      eql(exportedSeed, new Uint8Array(64));
      eql(providerSecret, new Uint8Array(31));
      const callsAfterFailure = calls;
      eql(await fresh.ml_kem512.isSupported(), false);
      eql(calls, callsAfterFailure);
    });
  });

  it('support probe cleans accepted secrets after decapsulation rejection', async () => {
    let exportedSeed: Uint8Array | undefined;
    let encapsulatedSecret: Uint8Array | undefined;
    let decapsulatedSecret: Uint8Array | undefined;
    let decapsulateCalls = 0;
    const subtle = {
      generateKey: async () => ({ privateKey: {}, publicKey: {} }),
      exportKey: async (format: string) => {
        const bytes = new Uint8Array(format === 'raw-seed' ? 64 : 800).fill(0x5a);
        if (format === 'raw-seed') exportedSeed = bytes;
        return bytes.buffer;
      },
      importKey: async () => ({}),
      getPublicKey: async () => ({}),
      encapsulateBits: async () => {
        encapsulatedSecret = new Uint8Array(32).fill(0xa5);
        return {
          ciphertext: new ArrayBuffer(768),
          sharedKey: encapsulatedSecret.buffer,
        };
      },
      decapsulateBits: async () => {
        decapsulateCalls++;
        decapsulatedSecret = new Uint8Array(31).fill(0xa5);
        return decapsulatedSecret.buffer;
      },
    };
    await withSubtle(subtle, async () => {
      const freshPath = '../src/webcrypto.ts?malformed-decapsulation-probe';
      const fresh = await import(freshPath);
      eql(await fresh.ml_kem512.isSupported(), false);
      eql(decapsulateCalls, 1);
      if (
        exportedSeed === undefined ||
        encapsulatedSecret === undefined ||
        decapsulatedSecret === undefined
      )
        throw new Error('expected provider secret outputs');
      eql(exportedSeed, new Uint8Array(64));
      eql(encapsulatedSecret, new Uint8Array(32));
      eql(decapsulatedSecret, new Uint8Array(31));
    });
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
