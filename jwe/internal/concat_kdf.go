package internal

import (
	"crypto"
)

// ConcatKDF implementation, as defined in Section 5.8.1 of [NIST.800-56A].
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
