import { test, expect } from '@playwright/test';
import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '../src/ml-dsa.ts';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = __dirname.includes('compiled')
  ? path.resolve(__dirname, '../../..')
  : path.resolve(__dirname, '..');

test.describe('noble-post-quantum WebCrypto ML-DSA Integration', () => {
  test.beforeEach(async ({ page }) => {
    // 1. Create a mocked secure context with importmap and route all requests
    await page.route('http://localhost:9999/**/*', async (route) => {
      const url = route.request().url();
      let relativePath = url.replace('http://localhost:9999/', '');

      // Serve the main HTML page
      if (relativePath === '') {
        await route.fulfill({
          status: 200,
          contentType: 'text/html',
          body: `
            <!DOCTYPE html>
            <html>
            <head>
              <script type="importmap">
              {
                "imports": {
                  "@noble/hashes/": "/node_modules/@noble/hashes/",
                  "@noble/curves/": "/node_modules/@noble/curves/"
                }
              }
              </script>
            </head>
            <body>
              <h1>Testing noble-post-quantum ML-DSA</h1>
            </body>
            </html>
          `,
        });
        return;
      }

      // If the browser requests a .ts file, serve the compiled .js file instead
      if (relativePath.endsWith('.ts')) {
        relativePath = relativePath.replace(/\.ts$/, '.js');
      }

      const filePath = path.resolve(rootDir, relativePath);
      const exists = fs.existsSync(filePath);

      if (exists && fs.statSync(filePath).isFile()) {
        await route.fulfill({
          status: 200,
          contentType: 'application/javascript',
          body: fs.readFileSync(filePath),
        });
      } else {
        await route.fulfill({ status: 404 });
      }
    });

    // 2. Inject a spy into window.crypto.subtle BEFORE the page loads
    await page.addInitScript(() => {
      (window as any).cryptoCalls = [];

      if (window.crypto && window.crypto.subtle) {
        const subtle = window.crypto.subtle;
        const methodsToSpy = ['generateKey', 'importKey', 'exportKey', 'sign', 'verify'];

        methodsToSpy.forEach((method) => {
          const original = (subtle as any)[method].bind(subtle);
          (subtle as any)[method] = async function (...args: any[]) {
            let algorithm = undefined;
            if (method === 'importKey') {
              algorithm = args[2]?.name || args[2];
            } else if (method === 'exportKey') {
              algorithm = args[1]?.algorithm?.name;
            } else {
              algorithm = args[0]?.name || args[0];
            }
            (window as any).cryptoCalls.push({ method, algorithm });
            return original(...args);
          };
        });
      }
    });

    page.on('console', (msg) => console.log('BROWSER CONSOLE:', msg.text()));
    page.on('pageerror', (err) => console.log('BROWSER PAGEERROR:', err.message));

    // 3. Navigate to the secure context
    await page.goto('http://localhost:9999/');
  });

  const parameterSets = [
    { name: 'ml_dsa44', publicKeyLength: 1312 },
    { name: 'ml_dsa65', publicKeyLength: 1952 },
    { name: 'ml_dsa87', publicKeyLength: 2592 },
  ];

  for (const { name, publicKeyLength } of parameterSets) {
    test(`keygen, sign, and verify hit WebCrypto and round-trip successfully - ${name}`, async ({
      page,
    }) => {
      const result = await page.evaluate(
        async ({ instanceName }) => {
          try {
            const mod = await import('http://localhost:9999/webcrypto_with_fallback.js');
            const dsa = (mod as any)[instanceName];

            // 1. Generate Keys (async)
            const keyPair = await dsa.keygen();
            (window as any).testSecretKey = keyPair.secretKey;

            const message = new Uint8Array([1, 2, 3, 4, 5]);

            // 2. Sign
            const sig = await dsa.sign(message, (window as any).testSecretKey);

            // 3. Verify
            const isValid = await dsa.verify(sig, message, keyPair.publicKey);

            return {
              success: true,
              isValid,
              recordedCalls: (window as any).cryptoCalls,
              publicKeyLength: keyPair.publicKey.byteLength,
              isCryptoKey: typeof keyPair.secretKey === 'object' && keyPair.secretKey.type === 'private',
            };
          } catch (error) {
            return { success: false, error: (error as Error).message };
          }
        },
        { instanceName: name }
      );

      expect(result.success, `Execution failed: ${result.error}`).toBe(true);
      expect(result.isValid, 'Signature verification failed!').toBe(true);
      expect(result.publicKeyLength).toBe(publicKeyLength);
      // expect(result.secretKeyLength).toBe(54); // WebCrypto PKCS8 format length for private keys
      // expect(result.isCryptoKey).toBe(true);

      const algName = name.replace('ml_dsa', 'ML-DSA-');
      expect(result.recordedCalls).toContainEqual({ method: 'generateKey', algorithm: algName });
      expect(result.recordedCalls).toContainEqual({ method: 'importKey', algorithm: algName });
      expect(result.recordedCalls).toContainEqual({ method: 'sign', algorithm: algName });
      expect(result.recordedCalls).toContainEqual({ method: 'verify', algorithm: algName });
    });

    test(`Cross-backend Interop: TS KeyGen/Verify <-> WebCrypto Sign - ${name}`, async ({ page }) => {
      // 1. (Node) Generate a keyPair using pure TS
      const tsMod = { ml_dsa44, ml_dsa65, ml_dsa87 } as any;
      const dsaTs = tsMod[name];
      const seed = new Uint8Array(32);
      seed.fill(4);
      const keyPairTs = dsaTs.keygen(seed);
      
      const message = new Uint8Array([1, 2, 3, 4, 5]);
      
      const secretKeyArray = Array.from(keyPairTs.secretKey);
      const messageArray = Array.from(message);
      
      // 2. (Browser) WebCrypto Sign
      const result = await page.evaluate(async ({ instanceName, sKey, msg }) => {
        try {
          const mod = await import('http://localhost:9999/webcrypto_with_fallback.js');
          const dsaWc = (mod as any)[instanceName];
          
          const secretKey = new Uint8Array(sKey);
          const messageBytes = new Uint8Array(msg);
          
          const signature = await dsaWc.sign(messageBytes, secretKey);
          
          return {
            success: true,
            signature: Array.from(signature)
          };
        } catch (error) {
          return { success: false, error: (error as Error).message };
        }
      }, { instanceName: name, sKey: secretKeyArray, msg: messageArray });
      
      expect(result.success, `WebCrypto sign failed: ${result.error}`).toBe(true);
      
      // 3. (Node) TS Verify
      const signatureTs = new Uint8Array(result.signature);
      const isValid = dsaTs.verify(signatureTs, message, keyPairTs.publicKey);
      
      expect(isValid).toBe(true);
    });

    test(`Cross-backend Interop: WebCrypto KeyGen/Verify <-> TS Sign - ${name}`, async ({ page }) => {
      const message = new Uint8Array([1, 2, 3, 4, 5]);
      const messageArray = Array.from(message);
      
      // 1. (Browser) WebCrypto KeyGen
      const result = await page.evaluate(async ({ instanceName }) => {
        try {
          const mod = await import('http://localhost:9999/webcrypto_with_fallback.js');
          const dsaWc = (mod as any)[instanceName];
          
          const keyPair = await dsaWc.keygen(undefined, { extractable: true });
          
          return {
            success: true,
            publicKey: Array.from(keyPair.publicKey),
            secretKey: Array.from(keyPair.secretKey as Uint8Array),
          };
        } catch (error) {
          return { success: false, error: (error as Error).message };
        }
      }, { instanceName: name });
      
      expect(result.success, `WebCrypto keygen failed: ${result.error}`).toBe(true);
      
      // 2. (Node) TS Sign
      const tsMod = { ml_dsa44, ml_dsa65, ml_dsa87 } as any;
      const dsaTs = tsMod[name];
      const secretKeyTs = new Uint8Array(result.secretKey);
      
      const derivedSecretKeyTs = dsaTs.keygen(secretKeyTs.subarray(22)).secretKey;
      const signatureTs = dsaTs.sign(message, derivedSecretKeyTs);
      const signatureArray = Array.from(signatureTs);
      const publicKeyArray = result.publicKey;
      
      // 3. (Browser) WebCrypto Verify
      const verifyResult = await page.evaluate(async ({ instanceName, sig, msg, pubKey }) => {
        try {
           const mod = await import('http://localhost:9999/webcrypto_with_fallback.js');
           const dsaWc = (mod as any)[instanceName];
           
           const signatureBytes = new Uint8Array(sig);
           const messageBytes = new Uint8Array(msg);
           const publicKeyBytes = new Uint8Array(pubKey);
           
           const isValid = await dsaWc.verify(signatureBytes, messageBytes, publicKeyBytes);
           return {
             success: true,
             isValid
           };
        } catch(error) {
           return { success: false, error: (error as Error).message };
        }
      }, { instanceName: name, sig: signatureArray, msg: messageArray, pubKey: publicKeyArray });
      
      expect(verifyResult.success, `WebCrypto verify failed: ${verifyResult.error}`).toBe(true);
      expect(verifyResult.isValid).toBe(true);
    });
  }

  test('Providing a seed bypasses WebCrypto and falls back to pure TS', async ({ page }) => {
    const result = await page.evaluate(async () => {
      const { ml_dsa44 } = await import('http://localhost:9999/webcrypto_with_fallback.js');

      (window as any).cryptoCalls = [];

      const seed = new Uint8Array(32);
      seed.fill(2);

      const keyPairPromise = ml_dsa44.keygen(seed);
      const isPromise = keyPairPromise instanceof Promise;
      const keyPair = await keyPairPromise;

      return {
        isPromise,
        recordedCalls: (window as any).cryptoCalls,
        secretKeyLen: keyPair.secretKey.byteLength,
      };
    });

    expect(result.isPromise).toBe(true);
    expect(result.recordedCalls.length).toBe(0);
    expect(result.secretKeyLen).toBeGreaterThan(1000); // TS secretKey is large
  });

  test('throws if WebCrypto sign throws an error instead of falling back', async ({ page }) => {
    const result = await page.evaluate(async () => {
      try {
        const { ml_dsa44 } = await import('http://localhost:9999/webcrypto_with_fallback.js');

        // Force native sign to fail
        window.crypto.subtle.sign = async () => {
          throw new DOMException('Simulated native failure', 'NotSupportedError');
        };

        (window as any).cryptoCalls = [];

        const keyPair = await ml_dsa44.keygen();
        const message = new Uint8Array([1, 2, 3, 4, 5]);
        await ml_dsa44.sign(message, keyPair.secretKey);

        return {
          success: true,
          recordedCalls: (window as any).cryptoCalls,
        };
      } catch (error) {
        return { success: false, error: (error as Error).message };
      }
    });

    expect(result.success).toBe(false);
    expect(result.error).toContain('Simulated native failure');
  });

  test('Context Testing: signing/verifying with context string fallback/handling', async ({
    page,
  }) => {
    const result = await page.evaluate(async () => {
      try {
        const { ml_dsa44 } = await import('http://localhost:9999/webcrypto_with_fallback.js');

        (window as any).cryptoCalls = [];

        const keyPair = await ml_dsa44.keygen();
        const message = new Uint8Array([1, 2, 3, 4, 5]);
        const context = new TextEncoder().encode("app-context-domain-separator");

        const sig = await ml_dsa44.sign(message, keyPair.secretKey, { context });
        const isValid = await ml_dsa44.verify(sig, message, keyPair.publicKey, { context });

        return {
          success: true,
          isValid,
          recordedCalls: (window as any).cryptoCalls,
        };
      } catch (error) {
        return { success: false, error: (error as Error).message };
      }
    });

    expect(result.success, `Execution failed: ${result.error}`).toBe(true);
    expect(result.isValid).toBe(true);
    expect(result.recordedCalls).toContainEqual({ method: 'generateKey', algorithm: 'ML-DSA-44' });
    expect(result.recordedCalls).toContainEqual({ method: 'sign', algorithm: 'ML-DSA-44' });
    expect(result.recordedCalls).toContainEqual({ method: 'verify', algorithm: 'ML-DSA-44' });
  });

  test('pure webcrypto.js throws when deterministic/custom inputs are used', async ({ page }) => {
    const result = await page.evaluate(async () => {
      const { ml_dsa44 } = await import('http://localhost:9999/webcrypto.js');
      let keygenThrew = false;
      let prehashThrew = false;
      try {
        await ml_dsa44.keygen(new Uint8Array(32));
      } catch (e) {
        keygenThrew = true;
      }
      try {
        await ml_dsa44.prehash();
      } catch (e) {
        prehashThrew = true;
      }
      return { keygenThrew, prehashThrew };
    });
    expect(result.keygenThrew).toBe(true);
    expect(result.prehashThrew).toBe(true);
  });
});
