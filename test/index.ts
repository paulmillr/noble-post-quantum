import { should } from '@paulmillr/jsbt/test.js';
import './acvp.test.ts';
import './basic.test.ts';
import './falcon.test.ts';
import './hybrid.test.ts';
// import './wycheproof.test.ts'; // run separately: npm run test:wycheproof
// import './errors.test.ts';

should.runWhen(import.meta.url);
