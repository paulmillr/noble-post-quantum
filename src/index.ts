/**
 * Auditable & minimal JS implementation of post-quantum public-key cryptography.
 * Check out individual modules.
 * @module
 * @example
```js
import { ml_kem512, ml_kem768, ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import {
  slh_dsa_sha2_128f, slh_dsa_sha2_128s,
  slh_dsa_sha2_192f, slh_dsa_sha2_192s,
  slh_dsa_sha2_256f, slh_dsa_sha2_256s,
  slh_dsa_shake_128f, slh_dsa_shake_128s,
  slh_dsa_shake_192f, slh_dsa_shake_192s,
  slh_dsa_shake_256f, slh_dsa_shake_256s,
} from '@noble/post-quantum/slh-dsa.js';
import {
  falcon512, falcon512padded, falcon1024, falcon1024padded,
} from '@noble/post-quantum/falcon.js';
import {
  ml_kem768_x25519, ml_kem768_p256, ml_kem1024_p384,
  KitchenSink_ml_kem768_x25519, XWing,
  QSF_ml_kem768_p256, QSF_ml_kem1024_p384,
} from '@noble/post-quantum/hybrid.js';
```
 */
throw new Error('root module cannot be imported: import submodules instead. Check out README');
