package internal

// The blank import registers SHA-256, which this package names, since crypto.Hash.New panics on a
// hash that no imported package registers.
import (
	_ "crypto/sha256"
)
