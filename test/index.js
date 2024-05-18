import { should } from 'micro-should';
import './ml-kem.test.js';
import './ml-dsa.test.js';
// requires 'cd vectors/ && ./build_kyber.sh'
import './big.test.js';

// ESM is broken.
import url from 'node:url';
if (import.meta.url === url.pathToFileURL(process.argv[1]).href) {
  //should.runParallel(); // 43 seconds
  should.run(); // 176 seconds
}
