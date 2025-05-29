import { should } from 'micro-should';
import './acvp.test.ts';
import './basic.test.ts';

should.runWhen(import.meta.url);
