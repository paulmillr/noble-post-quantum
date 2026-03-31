# Falcon Round-3 Source Fixtures

- `fpr.h` and `fpr.c` are vendored from the Falcon round-3 submission archive and used as the
  exact source oracles for `INV_SIGMA`, `SIGMA_MIN`, `BNORM_MAX`, and `COMPLEX_ROOTS` in
  `test/falcon.test.ts`.
- Upstream NIST archive URL:
  `https://csrc.nist.gov/CSRC/media/Projects/post-quantum-cryptography/documents/round-3/submissions/Falcon-Round3.zip`
- Verified archive sha256:
  `fd58f0454f6bfb4713734e60b2d2d75d96fbae62d5180fceeef1039df5362f44`
- Internal archive paths:
  - `Falcon/falcon-round3/Reference_Implementation/falcon512/falcon512int/fpr.h`
  - `Falcon/falcon-round3/Reference_Implementation/falcon512/falcon512int/fpr.c`
- Vendored `fpr.h` sha256:
  `f1ee79aa9cb59c6ac901820b95bcce9d32b9a2d845d26e94489bb3e05073ab84`
- Vendored `fpr.c` sha256:
  `98bb71888ccc8a7095d6af8785c6563ee9d8dbdfc383dc2c47edf2725a346043`
- `https://falcon-sign.info/falcon-round3.zip` has a different zip sha256
  (`d625407dbda9e5835f610aaeba1147e029988a6610e0107dfd292033138e1d47`), but the extracted
  contents match the NIST archive; the observed diff is the wrapper directory name
  (`falcon-round3/` vs `Falcon/falcon-round3/`).
