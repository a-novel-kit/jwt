package jws

// The blank imports register the hashes this package names, since crypto.Hash.New panics on a hash
// that no imported package registers. crypto/sha512 registers SHA-384 and SHA-512 both.
import (
	_ "crypto/sha256"
	_ "crypto/sha512"
)
