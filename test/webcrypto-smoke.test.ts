import { test, expect } from '@playwright/test';

test('debug: print browser version', async ({ browser }) => {
  console.log(`Running Chromium Engine Version: ${browser.version()}`);
});

test('WebCrypto ML-KEM-768 is fully enabled and functional', async ({ page }) => {
  await test.step('0. Navigate to a Secure Context', async () => {
    // 1. Intercept network requests to a fake localhost address
    await page.route('http://localhost:9999/', (route) => {
      route.fulfill({
        status: 200,
        contentType: 'text/html',
        body: '<html><body>Mocked Secure Context</body></html>',
      });
    });

    // 2. Navigate there so Chromium enables window.crypto.subtle
    await page.goto('http://localhost:9999/');
  });

  await test.step('1. Ensure SubtleCrypto is available', async () => {
    const hasSubtle = await page.evaluate(() => {
      return window.crypto && window.crypto.subtle !== undefined;
    });
    expect(hasSubtle, 'window.crypto.subtle should be defined').toBeTruthy();
  });

  await test.step('2. Generate ML-KEM-768 KeyPair', async () => {
    const keyGenState = await page.evaluate(async () => {
      try {
        // Generate keys and save them to the global window object for subsequent steps
        const kp = await window.crypto.subtle.generateKey(
          { name: 'ML-KEM-768' },
          true,
          ['encapsulateBits', 'decapsulateBits'] // Draft spec usages for KEMs
        );

        (window as any).pqcKeyPair = kp;

        return {
          success: true,
          pubAlgName: kp.publicKey.algorithm.name,
          privAlgName: kp.privateKey.algorithm.name,
        };
      } catch (error) {
        return { success: false, error: (error as Error).name };
      }
    });

    // If this fails, the PQC flag isn't working or the algorithm name is rejected
    expect(keyGenState.success, `Key generation failed: ${keyGenState.error}`).toBe(true);
    expect(keyGenState.pubAlgName).toBe('ML-KEM-768');
    expect(keyGenState.privAlgName).toBe('ML-KEM-768');
  });

  await test.step('3. Encapsulate a shared secret against the Public Key', async () => {
    const encapsState = await page.evaluate(async () => {
      try {
        // Cast subtle to any because standard TypeScript DOM types lack KEM methods currently
        const subtleAny = window.crypto.subtle as any;
        const kp = (window as any).pqcKeyPair;

        const { sharedKey, ciphertext } = await subtleAny.encapsulateBits(
          { name: 'ML-KEM-768' },
          kp.publicKey
        );

        // Save outputs to window for the decapsulation step
        (window as any).pqcCiphertext = ciphertext;
        (window as any).pqcSharedKey = sharedKey;

        return {
          success: true,
          sharedKeyByteLength: sharedKey.byteLength,
          ciphertextByteLength: ciphertext.byteLength,
        };
      } catch (error) {
        return { success: false, error: (error as Error).name };
      }
    });

    expect(encapsState.success, `Encapsulation failed: ${encapsState.error}`).toBe(true);

    // ML-KEM shared secrets are always 256-bit (32 bytes)
    expect(encapsState.sharedKeyByteLength).toBe(32);

    // ML-KEM-768 ciphertext is 1088 bytes according to FIPS 203 draft
    expect(encapsState.ciphertextByteLength).toBe(1088);
  });

  await test.step('4. Decapsulate the ciphertext using the Private Key', async () => {
    const decapsState = await page.evaluate(async () => {
      try {
        const subtleAny = window.crypto.subtle as any;
        const kp = (window as any).pqcKeyPair;
        const ciphertext = (window as any).pqcCiphertext;
        const originalSharedKey = (window as any).pqcSharedKey;

        // The receiver uses their private key to unpack the ciphertext
        const decapsulatedKey = await subtleAny.decapsulateBits(
          { name: 'ML-KEM-768' },
          kp.privateKey,
          ciphertext
        );

        // Compare the bytes to ensure both parties ended up with the identical secret
        const originalBytes = new Uint8Array(originalSharedKey);
        const decapsulatedBytes = new Uint8Array(decapsulatedKey);

        const isMatch =
          originalBytes.length === decapsulatedBytes.length &&
          originalBytes.every((val, i) => val === decapsulatedBytes[i]);

        return { success: true, isMatch };
      } catch (error) {
        return { success: false, error: (error as Error).name };
      }
    });

    expect(decapsState.success, `Decapsulation failed: ${decapsState.error}`).toBe(true);
    expect(
      decapsState.isMatch,
      'The decapsulated key must exactly match the encapsulated key'
    ).toBe(true);
  });
});

test('debug: print active chromium flags via CDP', async ({ browser }) => {
  // 1. Open a direct DevTools Protocol session with the browser engine
  const session = await browser.newBrowserCDPSession();

  // 2. Ask Chromium for the exact arguments it was launched with
  const result = await session.send('Browser.getBrowserCommandLine');

  console.log('Active Command Line Arguments:');
  console.log(result.arguments); // This prints the array of active flags

  // 3. Verify our experimental flag made it into the launch sequence
  expect(result.arguments).toContain('--enable-features=WebCryptoPQC');
});

test('spy on Web Crypto generateKey call', async ({ page }) => {
  // 1. Array to hold the intercepted calls in our Node environment
  const cryptoCalls: any[] = [];

  // 2. Expose a function so the browser can send data back to Playwright
  await page.exposeFunction('reportCryptoCall', (algorithm: any) => {
    cryptoCalls.push(algorithm);
  });

  // 3. Inject a script before the page loads to wrap the native API
  await page.addInitScript(() => {
    const originalGenerateKey = window.crypto.subtle.generateKey.bind(window.crypto.subtle);

    // @ts-ignore
    window.crypto.subtle.generateKey = async function (algorithm, extractable, keyUsages) {
      window.reportCryptoCall(algorithm);
      return originalGenerateKey(algorithm, extractable, keyUsages);
    };
  });

  // 4. FIX: Mock the route so we don't depend on a live server running on port 3000
  // This satisfies both the Secure Context constraint and the page navigation
  await page.route('https://pqc-test.local', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'text/html',
      body: '<html><body><h1>PQC Testing Sandbox</h1></body></html>',
    });
  });

  // Navigate to our secure, mocked domain
  await page.goto('https://pqc-test.local');

  // 5. Trigger the code right inside the browser context
  await page.evaluate(async () => {
    // This executes inside the browser, triggering our spy!
    await window.crypto.subtle.generateKey(
      { name: 'ML-KEM-768' },
      true,
      // FIX: Use the KEM-specific usages mandated by the WebCrypto spec
      ['encapsulateBits', 'decapsulateBits']
    );
  });

  // 6. Assert! Verify your spy caught the execution
  expect(cryptoCalls.length).toBeGreaterThan(0);
  expect(cryptoCalls[0].name).toBe('ML-KEM-768');
});
