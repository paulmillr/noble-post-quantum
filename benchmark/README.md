==== keygen ====
├─kyber512 x 3,723 ops/sec @ 268μs/op
├─kyber768 x 2,280 ops/sec @ 438μs/op
├─kyber1024 x 1,446 ops/sec @ 691μs/op
├─kyber512_90s x 7,086 ops/sec @ 141μs/op
├─kyber768_90s x 4,137 ops/sec @ 241μs/op
└─kyber1024_90s x 2,617 ops/sec @ 382μs/op
==== encrypt ====
├─kyber512 x 2,901 ops/sec @ 344μs/op
├─kyber768 x 1,812 ops/sec @ 551μs/op
├─kyber1024 x 1,196 ops/sec @ 836μs/op
├─kyber512_90s x 5,581 ops/sec @ 179μs/op
├─kyber768_90s x 3,426 ops/sec @ 291μs/op
└─kyber1024_90s x 2,278 ops/sec @ 438μs/op
==== decrypt ====
├─kyber512 x 3,407 ops/sec @ 293μs/op
├─kyber768 x 2,027 ops/sec @ 493μs/op
├─kyber1024 x 1,285 ops/sec @ 778μs/op
├─kyber512_90s x 6,099 ops/sec @ 163μs/op
├─kyber768_90s x 3,532 ops/sec @ 283μs/op
└─kyber1024_90s x 2,197 ops/sec @ 455μs/op
==== keygen ====
├─dilithium_v30_2 x 653 ops/sec @ 1ms/op
├─dilithium_v30_3 x 389 ops/sec @ 2ms/op
├─dilithium_v30_5 x 248 ops/sec @ 4ms/op
├─dilithium_v31_2 x 651 ops/sec @ 1ms/op
├─dilithium_v31_3 x 388 ops/sec @ 2ms/op
├─dilithium_v31_5 x 244 ops/sec @ 4ms/op
├─dilithium_v31_aes_2 x 873 ops/sec @ 1ms/op
├─dilithium_v31_aes_3 x 544 ops/sec @ 1ms/op
├─dilithium_v31_aes_5 x 359 ops/sec @ 2ms/op
├─ML-DSA44 x 650 ops/sec @ 1ms/op
├─ML-DSA65 x 389 ops/sec @ 2ms/op
└─ML-DSA87 x 245 ops/sec @ 4ms/op
==== sign ====
├─dilithium_v30_2 x 187 ops/sec @ 5ms/op
├─dilithium_v30_3 x 212 ops/sec @ 4ms/op
├─dilithium_v30_5 x 142 ops/sec @ 7ms/op
├─dilithium_v31_2 x 169 ops/sec @ 5ms/op
├─dilithium_v31_3 x 44 ops/sec @ 22ms/op
├─dilithium_v31_5 x 80 ops/sec @ 12ms/op
├─dilithium_v31_aes_2 x 167 ops/sec @ 5ms/op
├─dilithium_v31_aes_3 x 69 ops/sec @ 14ms/op
├─dilithium_v31_aes_5 x 101 ops/sec @ 9ms/op
├─ML-DSA44 x 117 ops/sec @ 8ms/op
├─ML-DSA65 x 33 ops/sec @ 29ms/op
└─ML-DSA87 x 38 ops/sec @ 26ms/op
==== verify ====
├─dilithium_v30_2 x 604 ops/sec @ 1ms/op
├─dilithium_v30_3 x 373 ops/sec @ 2ms/op
├─dilithium_v30_5 x 230 ops/sec @ 4ms/op
├─dilithium_v31_2 x 592 ops/sec @ 1ms/op
├─dilithium_v31_3 x 368 ops/sec @ 2ms/op
├─dilithium_v31_5 x 229 ops/sec @ 4ms/op
├─dilithium_v31_aes_2 x 740 ops/sec @ 1ms/op
├─dilithium_v31_aes_3 x 483 ops/sec @ 2ms/op
├─dilithium_v31_aes_5 x 316 ops/sec @ 3ms/op
├─ML-DSA44 x 592 ops/sec @ 1ms/op
├─ML-DSA65 x 369 ops/sec @ 2ms/op
└─ML-DSA87 x 229 ops/sec @ 4ms/op
==== keygen ====
├─sphincs_sha2_128f_simple x 226 ops/sec @ 4ms/op
├─sphincs_sha2_192f_simple x 155 ops/sec @ 6ms/op
├─sphincs_sha2_256f_simple x 59 ops/sec @ 16ms/op
├─sphincs_shake_128f_simple x 33 ops/sec @ 30ms/op
├─sphincs_shake_192f_simple x 22 ops/sec @ 43ms/op
└─sphincs_shake_256f_simple x 8 ops/sec @ 115ms/op
==== sign ====
├─sphincs_sha2_128f_simple x 9 ops/sec @ 103ms/op
├─sphincs_sha2_192f_simple x 5 ops/sec @ 177ms/op
├─sphincs_sha2_256f_simple x 2 ops/sec @ 362ms/op
├─sphincs_shake_128f_simple x 1 ops/sec @ 737ms/op
├─sphincs_shake_192f_simple x 0 ops/sec @ 1195ms/op
└─sphincs_shake_256f_simple x 0 ops/sec @ 2454ms/op
==== verify ====
├─sphincs_sha2_128f_simple x 148 ops/sec @ 6ms/op
├─sphincs_sha2_192f_simple x 101 ops/sec @ 9ms/op
├─sphincs_sha2_256f_simple x 103 ops/sec @ 9ms/op
├─sphincs_shake_128f_simple x 22 ops/sec @ 43ms/op
├─sphincs_shake_192f_simple x 15 ops/sec @ 64ms/op
└─sphincs_shake_256f_simple x 15 ops/sec @ 65ms/op

node v21, M2