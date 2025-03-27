import { should } from 'micro-should';
import './acvp.test.js';
import './basic.test.js';

should.runWhen(import.meta.url);
