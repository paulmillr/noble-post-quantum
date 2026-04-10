#!/bin/bash
set -euo pipefail

# Fetches Wycheproof test vectors from C2SP/wycheproof and gzips them.
# Run before test:wycheproof.

DIR="$(cd "$(dirname "$0")" && pwd)/vectors/wycheproof"
BASE="https://raw.githubusercontent.com/C2SP/wycheproof/master/testvectors_v1"

FILES=(
  mlkem_512_keygen_seed_test
  mlkem_512_test
  mlkem_512_encaps_test
  mlkem_768_keygen_seed_test
  mlkem_768_test
  mlkem_768_encaps_test
  mlkem_1024_keygen_seed_test
  mlkem_1024_test
  mlkem_1024_encaps_test
  mldsa_44_verify_test
  mldsa_44_sign_seed_test
  mldsa_65_verify_test
  mldsa_65_sign_seed_test
  mldsa_87_verify_test
  mldsa_87_sign_seed_test
)

mkdir -p "$DIR"

for f in "${FILES[@]}"; do
  dest="$DIR/${f}.json.gz"
  if [ -f "$dest" ]; then
    echo "skip $f (cached)"
    continue
  fi
  echo "fetch $f"
  curl -sfL "${BASE}/${f}.json" | gzip > "$dest"
done

echo "done: $(find "$DIR" -name '*.json.gz' | wc -l | tr -d ' ') vector files"
