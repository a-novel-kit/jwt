package jwek

// The blank imports register the hashes this package names, since crypto.Hash.New panics on a hash
// that no imported package registers. crypto/sha512 registers SHA-384 and SHA-512 both, and
// crypto/sha1 backs the deprecated RSAOAEP preset.
import (
	_ "crypto/sha1" //nolint:gosec // RSA-OAEP is registered with SHA-1.
	_ "crypto/sha256"
	_ "crypto/sha512"
)
