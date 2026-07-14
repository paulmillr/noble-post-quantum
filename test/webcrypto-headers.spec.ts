import { test, expect } from '@playwright/test';
import { ML_KEM_OIDS, ML_DSA_OIDS } from '../src/webcrypto.ts';
import { wrapSPKI, unwrapSPKI } from '../src/utils.ts';

test.describe('WebCrypto Native SPKI Headers Validation', () => {
  test.beforeEach(async ({ page }) => {
    await page.route('https://pqc-test.local/', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'text/html',
        body: '<html><body>PQC Testing Sandbox</body></html>',
      });
    });
    await page.goto('https://pqc-test.local/');
  });

  const KEM_ALGS = [
    { name: 'ML-KEM-512', k: 2 },
    { name: 'ML-KEM-768', k: 3 },
    { name: 'ML-KEM-1024', k: 4 },
  ];

  for (const alg of KEM_ALGS) {
    test(`Native ${alg.name} SPKI can be unwrapped and re-wrapped to match exactly`, async ({ page }) => {
      const spkiArray = await page.evaluate(async ({ algName }) => {
        try {
          const kp = await window.crypto.subtle.generateKey(
            { name: algName } as any,
            true,
            ['encapsulateBits', 'decapsulateBits'] as any
          );
          const spkiBuffer = await window.crypto.subtle.exportKey('spki', kp.publicKey);
          return Array.from(new Uint8Array(spkiBuffer as ArrayBuffer));
        } catch (error) {
          if ((error as Error).name === 'NotSupportedError') return null;
          throw error;
        }
      }, { algName: alg.name });

      if (spkiArray === null) {
        test.skip(true, `${alg.name} not natively supported in this browser version.`);
        return;
      }

      const spkiBytes = new Uint8Array(spkiArray);
      const oid = ML_KEM_OIDS[alg.k];
      
      expect(oid).toBeDefined();
      
      const rawKey = unwrapSPKI(spkiBytes);
      const rewrappedSpki = wrapSPKI(oid, rawKey);
      
      expect(rewrappedSpki).toEqual(spkiBytes);
    });
  }

  const DSA_ALGS = [
    { name: 'ML-DSA-44', k: 4 },
    { name: 'ML-DSA-65', k: 6 },
    { name: 'ML-DSA-87', k: 8 },
  ];

  for (const alg of DSA_ALGS) {
    test(`Native ${alg.name} SPKI can be unwrapped and re-wrapped to match exactly`, async ({ page }) => {
      const spkiArray = await page.evaluate(async ({ algName }) => {
        try {
          const kp = await window.crypto.subtle.generateKey(
            { name: algName } as any,
            true,
            ['sign', 'verify'] as any
          );
          const spkiBuffer = await window.crypto.subtle.exportKey('spki', kp.publicKey);
          return Array.from(new Uint8Array(spkiBuffer as ArrayBuffer));
        } catch (error) {
          if ((error as Error).name === 'NotSupportedError') return null;
          throw error;
        }
      }, { algName: alg.name });

      if (spkiArray === null) {
        test.skip(true, `${alg.name} not natively supported in this browser version.`);
        return;
      }

      const spkiBytes = new Uint8Array(spkiArray);
      const oid = ML_DSA_OIDS[alg.k];
      
      expect(oid).toBeDefined();
      
      const rawKey = unwrapSPKI(spkiBytes);
      const rewrappedSpki = wrapSPKI(oid, rawKey);
      
      expect(rewrappedSpki).toEqual(spkiBytes);
    });
  }
});
