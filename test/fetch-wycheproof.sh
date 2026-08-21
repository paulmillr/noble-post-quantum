#!/bin/bash
set -euo pipefail

# Fetches Wycheproof test vectors from C2SP/wycheproof and gzips them.
# Run before test:wycheproof.

DIR="$(cd "$(dirname "$0")" && pwd)/vectors/wycheproof"
# Pinned to a commit, not a branch. A moving ref makes a refresh unreproducible, and
# "master" only resolves at all because GitHub still redirects it after the rename to
# "main", which is not something to depend on. Bump deliberately.
REF="dac1dd4729fd1f8dd9e1e9f3dce51d783da6c166"
BASE="https://raw.githubusercontent.com/C2SP/wycheproof/${REF}/testvectors_v1"

FILES=(
  mlkem_512_keygen_seed_test
  mlkem_512_test
  mlkem_512_encaps_test
  mlkem_512_semi_expanded_decaps_test
  mlkem_768_keygen_seed_test
  mlkem_768_test
  mlkem_768_encaps_test
  mlkem_768_semi_expanded_decaps_test
  mlkem_1024_keygen_seed_test
  mlkem_1024_test
  mlkem_1024_encaps_test
  mlkem_1024_semi_expanded_decaps_test
  mldsa_44_verify_test
  mldsa_44_sign_seed_test
  mldsa_44_sign_noseed_test
  mldsa_65_verify_test
  mldsa_65_sign_seed_test
  mldsa_65_sign_noseed_test
  mldsa_87_verify_test
  mldsa_87_sign_seed_test
  mldsa_87_sign_noseed_test
)

mkdir -p "$DIR"

for f in "${FILES[@]}"; do
  dest="$DIR/${f}.json.gz"
  if [ -f "$dest" ]; then
    echo "skip $f (cached)"
    continue
  fi
  echo "fetch $f"
  # Write to a temp file and move only on success. Redirecting straight to $dest
  # makes the shell create it before curl runs, so a network failure leaves a valid
  # gzip archive of nothing (20 bytes, passes `gzip -t`). The cached-file check above
  # then skips it forever, the loader finds no testGroups, every vector loop runs zero
  # iterations, and the suite reports green while testing nothing.
  tmp="${dest}.part"
  if curl -sfL "${BASE}/${f}.json" | gzip > "$tmp"; then
    mv "$tmp" "$dest"
  else
    rm -f "$tmp"
    echo "FAILED to fetch $f" >&2
    exit 1
  fi
done

echo "done: $(find "$DIR" -name '*.json.gz' | wc -l | tr -d ' ') vector files"
