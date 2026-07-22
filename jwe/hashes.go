package jwe

// Link in the hash implementations this package's presets name.
//
// crypto.Hash is a registry of identifiers, not implementations: crypto.SHA256 is a number, and
// calling New on it panics with "requested hash function #5 is unavailable" unless something has
// linked the implementation in. The standard library's hash packages register themselves from init,
// so naming a hash without importing one leaves that to whoever imports this package — and a
// consumer that imports only jwt and this package panics on its first operation, at run time,
// having built cleanly.
//
// crypto/sha512 registers SHA-384 and SHA-512 both.
import (
	_ "crypto/sha256"
	_ "crypto/sha512"
)
