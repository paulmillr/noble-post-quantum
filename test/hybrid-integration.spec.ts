import { test, expect } from '@playwright/test';
import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';
import { ml_kem768_x25519 } from '../src/hybrid.ts';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = __dirname.includes('compiled')
  ? path.resolve(__dirname, '../../..')
  : path.resolve(__dirname, '..');

test.describe('noble-post-quantum WebCrypto Hybrid Integration', () => {
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
              <h1>Testing noble-post-quantum</h1>
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
      console.log(`[ROUTE DEBUG] url=${url} resolvedPath=${filePath} exists=${exists}`);

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
        const methodsToSpy = [
          'generateKey',
          'importKey',
          'exportKey',
          'encapsulateBits',
          'decapsulateBits',
        ];

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
    page.on('requestfailed', (req) =>
      console.log('BROWSER REQUEST FAILED:', req.url(), req.failure()?.errorText)
    );

    // 3. Navigate to the secure context
    await page.goto('http://localhost:9999/');
  });

  test('X-Wing keygen, encapsulate, and decapsulate hit WebCrypto and round-trip successfully', async ({
    page,
  }) => {
    const result = await page.evaluate(async () => {
      try {
        const mod = await import('http://localhost:9999/webcrypto_with_fallback.js');
        const kem = mod.MLKEM768X25519;

        // 1. Key Generation
        const keyPair = await kem.keygen();
        (window as any).testSecretKey = keyPair.secretKey;

        // 2. Encapsulation
        const { cipherText, sharedSecret: senderSecret } = await kem.encapsulate(keyPair.publicKey);

        // 3. Decapsulation
        const receiverSecret = await kem.decapsulate(cipherText, (window as any).testSecretKey);

        // 4. Verify Correctness
        const senderBytes = new Uint8Array(senderSecret);
        const receiverBytes = new Uint8Array(receiverSecret);
        const isMatch =
          senderBytes.length === receiverBytes.length &&
          senderBytes.every((val, i) => val === receiverBytes[i]);

        return {
          success: true,
          isMatch,
          recordedCalls: (window as any).cryptoCalls,
          publicKeyLength: keyPair.publicKey.byteLength,
          isCryptoKey: typeof keyPair.secretKey === 'object' && keyPair.secretKey.type === 'private',
          cipherTextLength: cipherText.byteLength,
        };
      } catch (error) {
        return { success: false, error: (error as Error).message };
      }
    });

    expect(result.success, `Execution failed: ${result.error}`).toBe(true);
    expect(result.isMatch, 'Sender and Receiver shared secrets do not match!').toBe(true);
    expect(result.publicKeyLength).toBe(1216);
    // expect(result.secretKeyLength).toBe(1248);
    // expect(result.isCryptoKey).toBe(true);
    expect(result.cipherTextLength).toBe(1120);

    // Verify SubtleCrypto was called with the correct algorithm name
    expect(result.recordedCalls).toContainEqual({ method: 'generateKey', algorithm: 'MLKEM768-X25519' });
    expect(result.recordedCalls).toContainEqual({ method: 'exportKey', algorithm: 'MLKEM768-X25519' });
    expect(result.recordedCalls).toContainEqual({ method: 'importKey', algorithm: 'MLKEM768-X25519' });
    expect(result.recordedCalls).toContainEqual({ method: 'encapsulateBits', algorithm: 'MLKEM768-X25519' });
    expect(result.recordedCalls).toContainEqual({ method: 'decapsulateBits', algorithm: 'MLKEM768-X25519' });
  });

  test('Cross-backend Interop: TS KeyGen/Decapsulate <-> WebCrypto Encapsulate - X-Wing', async ({ page }) => {
    // 1. (Node) Generate a keyPair using pure TS
    const kemTs = ml_kem768_x25519;
    const seed = new Uint8Array(32);
    seed.fill(3);
    const keyPairTs = kemTs.keygen(seed);
    
    // We must serialize the publicKey to an array to pass it to page.evaluate
    const publicKeyArray = Array.from(keyPairTs.publicKey);
    
    const result = await page.evaluate(async ({ pubKey }) => {
      try {
        const mod = await import('http://localhost:9999/webcrypto_with_fallback.js');
        const kemWc = mod.MLKEM768X25519;
        
        // 2. (Browser) WebCrypto Encapsulate
        const publicKey = new Uint8Array(pubKey);
        const { cipherText, sharedSecret } = await kemWc.encapsulate(publicKey);
        
        return {
          success: true,
          cipherText: Array.from(cipherText),
          sharedSecret: Array.from(sharedSecret),
        };
      } catch (error) {
        return { success: false, error: (error as Error).message };
      }
    }, { pubKey: publicKeyArray });
    
    expect(result.success, `WebCrypto encapsulate failed: ${result.error}`).toBe(true);
    
    // 3. (Node) TS Decapsulate
    const cipherTextTs = new Uint8Array(result.cipherText);
    const decapsulatedSecretTs = kemTs.decapsulate(cipherTextTs, keyPairTs.secretKey);
    
    const webCryptoSecret = new Uint8Array(result.sharedSecret);
    
    // Assert they match
    expect(decapsulatedSecretTs).toEqual(webCryptoSecret);
  });

  test('Cross-backend Interop: WebCrypto KeyGen/Decapsulate <-> TS Encapsulate - X-Wing', async ({ page }) => {
    const result = await page.evaluate(async () => {
      try {
        const mod = await import('http://localhost:9999/webcrypto_with_fallback.js');
        const kemWc = mod.MLKEM768X25519;
        
        // 1. (Browser) WebCrypto KeyGen with extractable: true
        const keyPair = await kemWc.keygen(undefined, { extractable: true });
        
        return {
          success: true,
          publicKey: Array.from(keyPair.publicKey),
          secretKey: Array.from(keyPair.secretKey),
        };
      } catch (error) {
        return { success: false, error: (error as Error).message };
      }
    });
    
    expect(result.success, `WebCrypto keygen failed: ${result.error}`).toBe(true);
    
    // 2. (Node) TS Encapsulate
    const kemTs = ml_kem768_x25519;
    const pubKeyTs = new Uint8Array(result.publicKey);
    
    const { cipherText, sharedSecret: tsSharedSecret } = kemTs.encapsulate(pubKeyTs);
    
    const cipherTextArray = Array.from(cipherText);
    const secretKeyArray = result.secretKey;
    
    // 3. (Browser) WebCrypto Decapsulate
    const decapsResult = await page.evaluate(async ({ cText, sKey }) => {
      try {
         const mod = await import('http://localhost:9999/webcrypto_with_fallback.js');
         const kemWc = mod.MLKEM768X25519;
         const cipherTextBytes = new Uint8Array(cText);
         const secretKeyBytes = new Uint8Array(sKey);
         
         const wcDecapsulatedSecret = await kemWc.decapsulate(cipherTextBytes, secretKeyBytes);
         return {
           success: true,
           wcSharedSecret: Array.from(wcDecapsulatedSecret)
         };
      } catch(error) {
         return { success: false, error: (error as Error).message };
      }
    }, { cText: cipherTextArray, sKey: secretKeyArray });
    
    expect(decapsResult.success, `WebCrypto decapsulate failed: ${decapsResult.error}`).toBe(true);
    
    const webCryptoSecret = new Uint8Array(decapsResult.wcSharedSecret);
    expect(tsSharedSecret).toEqual(webCryptoSecret);
  });

  test('Providing a seed bypasses WebCrypto and falls back to pure TS', async ({ page }) => {
    const result = await page.evaluate(async () => {
      const mod = await import('http://localhost:9999/webcrypto_with_fallback.js');
      const kem = mod.MLKEM768X25519;

      (window as any).cryptoCalls = [];

      const seed = new Uint8Array(32);
      seed.fill(1);

      const keyPairPromise = kem.keygen(seed);
      const isPromise = keyPairPromise instanceof Promise;
      const keyPair = await keyPairPromise;

      return {
        isPromise,
        recordedCalls: (window as any).cryptoCalls,
      };
    });

    expect(result.isPromise).toBe(true);
    expect(result.recordedCalls.length).toBe(0);
  });

  test('throws if WebCrypto throws an error instead of falling back', async ({ page }) => {
    const result = await page.evaluate(async () => {
      try {
        const mod = await import('http://localhost:9999/webcrypto_with_fallback.js');
        const kem = mod.MLKEM768X25519;

        // Mock failure on encapsulateBits
        window.crypto.subtle.encapsulateBits = async () => {
          throw new DOMException('Simulated native failure', 'NotSupportedError');
        };

        (window as any).cryptoCalls = [];

        const keyPair = await kem.keygen();
        await kem.encapsulate(keyPair.publicKey);

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

  test('pure webcrypto.js throws when deterministic/custom inputs are used', async ({ page }) => {
    const result = await page.evaluate(async () => {
      const { ml_kem768_x25519 } = await import('http://localhost:9999/webcrypto.js');
      let keygenThrew = false;
      let encapsulateThrew = false;
      let decapsulateThrew = false;
      try {
        await ml_kem768_x25519.keygen(new Uint8Array(32));
      } catch (e) {
        keygenThrew = true;
      }
      try {
        const keyPair = await ml_kem768_x25519.keygen();
        await ml_kem768_x25519.encapsulate(keyPair.publicKey, new Uint8Array(64));
      } catch (e) {
        encapsulateThrew = true;
      }
      try {
        await ml_kem768_x25519.decapsulate(new Uint8Array(1120), new Uint8Array(32));
      } catch (e) {
        decapsulateThrew = true;
      }
      return { keygenThrew, encapsulateThrew, decapsulateThrew };
    });
    expect(result.keygenThrew).toBe(true);
    expect(result.encapsulateThrew).toBe(true);
    expect(result.decapsulateThrew).toBe(true);
  });

});
