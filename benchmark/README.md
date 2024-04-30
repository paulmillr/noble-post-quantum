
```
==== keygen ====
├─kyber512 x 3,532 ops/sec @ 283μs/op
├─kyber768 x 2,172 ops/sec @ 460μs/op
├─kyber1024 x 1,368 ops/sec @ 730μs/op
├─kyber512_90s x 6,572 ops/sec @ 152μs/op
├─kyber768_90s x 3,838 ops/sec @ 260μs/op
├─kyber1024_90s x 2,436 ops/sec @ 410μs/op
├─ML-KEM-512 x 3,503 ops/sec @ 285μs/op
├─ML-KEM-768 x 2,150 ops/sec @ 465μs/op
└─ML-KEM-1024 x 1,360 ops/sec @ 734μs/op
==== encrypt ====
├─kyber512 x 2,694 ops/sec @ 371μs/op
├─kyber768 x 1,709 ops/sec @ 584μs/op
├─kyber1024 x 1,129 ops/sec @ 885μs/op
├─kyber512_90s x 5,263 ops/sec @ 190μs/op
├─kyber768_90s x 3,248 ops/sec @ 307μs/op
├─kyber1024_90s x 2,137 ops/sec @ 467μs/op
├─ML-KEM-512 x 3,111 ops/sec @ 321μs/op
├─ML-KEM-768 x 1,893 ops/sec @ 528μs/op
└─ML-KEM-1024 x 1,246 ops/sec @ 802μs/op
==== decrypt ====
├─kyber512 x 3,130 ops/sec @ 319μs/op
├─kyber768 x 1,869 ops/sec @ 534μs/op
├─kyber1024 x 1,190 ops/sec @ 839μs/op
├─kyber512_90s x 5,436 ops/sec @ 183μs/op
├─kyber768_90s x 3,237 ops/sec @ 308μs/op
├─kyber1024_90s x 2,006 ops/sec @ 498μs/op
├─ML-KEM-512 x 3,267 ops/sec @ 305μs/op
├─ML-KEM-768 x 1,925 ops/sec @ 519μs/op
└─ML-KEM-1024 x 1,228 ops/sec @ 813μs/op
==== keygen ====
├─dilithium_v30_2 x 606 ops/sec @ 1ms/op
├─dilithium_v30_3 x 365 ops/sec @ 2ms/op
├─dilithium_v30_5 x 233 ops/sec @ 4ms/op
├─dilithium_v31_2 x 617 ops/sec @ 1ms/op
├─dilithium_v31_3 x 369 ops/sec @ 2ms/op
├─dilithium_v31_5 x 230 ops/sec @ 4ms/op
├─dilithium_v31_aes_2 x 820 ops/sec @ 1ms/op
├─dilithium_v31_aes_3 x 506 ops/sec @ 1ms/op
├─dilithium_v31_aes_5 x 341 ops/sec @ 2ms/op
├─ML-DSA44 x 614 ops/sec @ 1ms/op
├─ML-DSA65 x 368 ops/sec @ 2ms/op
└─ML-DSA87 x 233 ops/sec @ 4ms/op
==== sign ====
├─dilithium_v30_2 x 175 ops/sec @ 5ms/op
├─dilithium_v30_3 x 201 ops/sec @ 4ms/op
├─dilithium_v30_5 x 134 ops/sec @ 7ms/op
├─dilithium_v31_2 x 160 ops/sec @ 6ms/op
├─dilithium_v31_3 x 41 ops/sec @ 23ms/op
├─dilithium_v31_5 x 77 ops/sec @ 12ms/op
├─dilithium_v31_aes_2 x 159 ops/sec @ 6ms/op
├─dilithium_v31_aes_3 x 66 ops/sec @ 15ms/op
├─dilithium_v31_aes_5 x 96 ops/sec @ 10ms/op
├─ML-DSA44 x 112 ops/sec @ 8ms/op
├─ML-DSA65 x 31 ops/sec @ 31ms/op
└─ML-DSA87 x 36 ops/sec @ 27ms/op
==== verify ====
├─dilithium_v30_2 x 568 ops/sec @ 1ms/op
├─dilithium_v30_3 x 356 ops/sec @ 2ms/op
├─dilithium_v30_5 x 221 ops/sec @ 4ms/op
├─dilithium_v31_2 x 571 ops/sec @ 1ms/op
├─dilithium_v31_3 x 355 ops/sec @ 2ms/op
├─dilithium_v31_5 x 221 ops/sec @ 4ms/op
├─dilithium_v31_aes_2 x 712 ops/sec @ 1ms/op
├─dilithium_v31_aes_3 x 465 ops/sec @ 2ms/op
├─dilithium_v31_aes_5 x 306 ops/sec @ 3ms/op
├─ML-DSA44 x 570 ops/sec @ 1ms/op
├─ML-DSA65 x 355 ops/sec @ 2ms/op
└─ML-DSA87 x 220 ops/sec @ 4ms/op
==== keygen ====
├─sphincs_sha2_128f_simple x 208 ops/sec @ 4ms/op
├─sphincs_sha2_192f_simple x 145 ops/sec @ 6ms/op
├─sphincs_sha2_256f_simple x 56 ops/sec @ 17ms/op
├─sphincs_shake_128f_simple x 31 ops/sec @ 31ms/op
├─sphincs_shake_192f_simple x 21 ops/sec @ 45ms/op
└─sphincs_shake_256f_simple x 8 ops/sec @ 120ms/op
==== sign ====
├─sphincs_sha2_128f_simple x 9 ops/sec @ 109ms/op
├─sphincs_sha2_192f_simple x 5 ops/sec @ 188ms/op
├─sphincs_sha2_256f_simple x 2 ops/sec @ 384ms/op
├─sphincs_shake_128f_simple x 1 ops/sec @ 735ms/op
├─sphincs_shake_192f_simple x 0 ops/sec @ 1188ms/op
└─sphincs_shake_256f_simple x 0 ops/sec @ 2443ms/op
==== verify ====
├─sphincs_sha2_128f_simple x 140 ops/sec @ 7ms/op
├─sphincs_sha2_192f_simple x 91 ops/sec @ 10ms/op
├─sphincs_sha2_256f_simple x 98 ops/sec @ 10ms/op
├─sphincs_shake_128f_simple x 22 ops/sec @ 45ms/op
├─sphincs_shake_192f_simple x 15 ops/sec @ 64ms/op
└─sphincs_shake_256f_simple x 15 ops/sec @ 64ms/op
```

node v21.2.0, M1 Pro
