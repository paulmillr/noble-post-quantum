import { should } from '@paulmillr/jsbt/test.js';
import './acvp.test.ts';
import './basic.test.ts';
import './falcon.test.ts';
import './hybrid.test.ts';
import './wycheproof.test.ts';

should.runWhen(import.meta.url);
