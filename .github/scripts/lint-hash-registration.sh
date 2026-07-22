#!/usr/bin/env bash
# Every package that names a crypto.Hash must link the implementation in.
#
# crypto.Hash is a registry of identifiers, not implementations. crypto.SHA256 is a number, and
# New() on it panics with "requested hash function #5 is unavailable" unless some package has
# registered SHA-256 from its init. The standard library's hash packages do that for themselves, so
# a package naming a hash without importing one leaves the job to its consumer.
#
# That failure cannot be caught by the test suite. A test binary pulls in the hash packages through
# its own dependencies — testify, crypto/ecdsa — so every hash reads as available no matter what the
# library imports. Only a consumer importing the library alone finds out, at run time, in
# production, having built cleanly.
#
# So the rule is checked structurally: name a hash, import its registrar.
set -euo pipefail

ROOT="${1:-.}"

# hash identifier -> the standard library package whose init registers it
declare -A REGISTRAR=(
  [SHA1]=crypto/sha1
  [SHA224]=crypto/sha256
  [SHA256]=crypto/sha256
  [SHA384]=crypto/sha512
  [SHA512]=crypto/sha512
)

fail=0

# Package directories holding non-test Go sources that name a hash.
while IFS= read -r dir; do
  used=$(grep -rhoE 'crypto\.SHA[0-9]+' "$dir"/*.go 2>/dev/null |
    grep -v '_test.go' | sed 's/crypto\.//' | sort -u || true)
  [ -n "$used" ] || continue

  for hash in $used; do
    registrar="${REGISTRAR[$hash]:-}"
    if [ -z "$registrar" ]; then
      echo "::error file=${dir}::crypto.${hash} has no known registrar in this check — add one to REGISTRAR."
      fail=1

      continue
    fi

    # The blank import may live in any non-test file of the package.
    if ! grep -rqE "^[[:space:]]*_ \"${registrar}\"" "$dir"/*.go 2>/dev/null; then
      echo "::error file=${dir}::package names crypto.${hash} but no file imports \`_ \"${registrar}\"\`, so calling New() on it panics for a consumer that imports this package alone. Add the blank import (see hashes.go)."
      fail=1
    fi
  done
done < <(find "$ROOT" -type f -name '*.go' -not -name '*_test.go' -not -path '*/node_modules/*' \
  -exec dirname {} \; | sort -u)

if [ "$fail" -ne 0 ]; then
  exit 1
fi

echo "✓ every package naming a crypto.Hash imports its registrar."
