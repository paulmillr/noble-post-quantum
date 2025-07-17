import { should } from 'micro-should';
import './acvp.test.ts';
import './basic.test.ts';
import './hybrid.test.ts';

should.runWhen(import.meta.url);
