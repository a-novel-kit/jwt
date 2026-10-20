#!/usr/bin/env bash
# Every package that names a crypto.Hash must link the implementation in.
#
# crypto.Hash is a registry of identifiers, not implementations. crypto.SHA256 is a number, and
# New() on it panics with "requested hash function #5 is unavailable" unless some package has
# registered SHA-256 from its init. The standard library's hash packages do that for themselves, so
# a package naming a hash without importing one leaves the job to its consumer.
#
# That failure cannot be caught by the test suite. A test binary pulls in the hash packages through
# its own dependencies, such as testify and crypto/ecdsa, so every hash reads as available no matter
# what the library imports. Only a consumer importing the library alone finds out, at run time, in
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

# Each directory holding non-test Go sources is one package. Its test files never reach a consumer,
# so they neither count as naming a hash nor as importing a registrar.
while IFS= read -r dir; do
  sources=()
  for file in "$dir"/*.go; do
    [[ "$file" == *_test.go ]] || sources+=("$file")
  done

  used=$(grep -hoE 'crypto\.SHA[0-9]+' "${sources[@]}" | sed 's/crypto\.//' | sort -u || true)
  [ -n "$used" ] || continue

  for hash in $used; do
    registrar="${REGISTRAR[$hash]:-}"
    if [ -z "$registrar" ]; then
      printf '::error file=%s::crypto.%s has no known registrar in this check. Add one to REGISTRAR.\n' \
        "$dir" "$hash"
      fail=1

      continue
    fi

    if ! grep -qE "^[[:space:]]*_ \"${registrar}\"" "${sources[@]}"; then
      printf '::error file=%s::package names crypto.%s but no file imports %s, so calling New() on it panics for a consumer that imports this package alone. Add the blank import (see hashes.go).\n' \
        "$dir" "$hash" "\`_ \"${registrar}\"\`"
      fail=1
    fi
  done
done < <(find "$ROOT" -type f -name '*.go' -not -name '*_test.go' -not -path '*/node_modules/*' \
  -exec dirname {} \; | sort -u)

if [ "$fail" -ne 0 ]; then
  exit 1
fi

printf '✓ every package naming a crypto.Hash imports its registrar.\n'
