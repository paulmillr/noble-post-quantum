import { should } from '@paulmillr/jsbt/test.js';
import * as jsPlatform from '@awasm/noble/js.js';
import * as stubs from '@awasm/noble/stub.js';
import * as wasmPlatform from '@awasm/noble/wasm.js';
import * as wasmThreadsPlatform from '@awasm/noble/wasm_threads.js';
// import './errors.test.ts';

const platforms = {
  js: jsPlatform,
  wasm: wasmPlatform,
  wasm_threads: wasmThreadsPlatform,
} as const;
const platformName =
  typeof process === 'undefined' ? undefined : (process.argv[2] as keyof typeof platforms);
if (platformName !== undefined) {
  const platform = platforms[platformName];
  if (!platform) throw new Error(`unknown test platform: ${platformName}`);
  for (const name in platform) {
    const stub = stubs[name as keyof typeof stubs];
    const impl = platform[name as keyof typeof platform];
    if (stub && 'install' in stub && impl) stub.install(impl);
  }
}

await import('./acvp.test.ts');
await import('./basic.test.ts');
await import('./falcon.test.ts');
await import('./hybrid.test.ts');
await import('./wycheproof.test.ts');

should.runWhen(import.meta.url);
