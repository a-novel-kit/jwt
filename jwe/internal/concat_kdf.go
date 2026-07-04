// Package internal holds the low-level cryptographic primitives that the JWE key-management
// algorithms compose: key derivation, key wrapping, and padding. They live here so several
// algorithm implementations can share one vetted implementation of each primitive instead of
// duplicating it.
package internal

import (
	"crypto"
)

// ConcatKDF derives keyDataLen bytes of key material from the shared secret z, following the
// single-step Concatenation KDF defined in NIST SP 800-56A. The remaining arguments are hashed
// alongside z on every iteration as the KDF's OtherInfo.
func ConcatKDF(
	hash crypto.Hash, z []byte, keyDataLen int, algID, pUInfo, pVInfo, supPubInfo, supPrivInfo []byte,
) []byte {
	buffer := make([]byte, 4+len(z)+len(algID)+len(pUInfo)+len(pVInfo)+len(supPubInfo)+len(supPrivInfo))

	// Concatenate all inputs.
	n := 0
	n += copy(buffer[n:], []byte{0, 0, 0, 1})
	n += copy(buffer[n:], z)
	n += copy(buffer[n:], algID)
	n += copy(buffer[n:], pUInfo)
	n += copy(buffer[n:], pVInfo)
	n += copy(buffer[n:], supPubInfo)
	copy(buffer[n:], supPrivInfo)

	h := hash.New()
	output := make([]byte, 0, keyDataLen)

	for len(output) < keyDataLen {
		h.Write(buffer)
		output = h.Sum(output)
		h.Reset()
	}

	return output[:keyDataLen]
}
