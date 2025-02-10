package internal_test

import (
	"crypto"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt/jwe/internal"
)

// https://datatracker.ietf.org/doc/html/rfc7518#appendix-C
func TestVectorConcatKDF(t *testing.T) {
	t.Parallel()

	z := []byte{
		158, 86, 217, 29, 129, 113, 53, 211, 114, 131, 66, 131, 191, 132,
		38, 156, 251, 49, 110, 163, 218, 128, 106, 72, 246, 218, 167, 121,
		140, 254, 144, 196,
	}

	algID := []byte{0, 0, 0, 7, 65, 49, 50, 56, 71, 67, 77}

	ptyUInfo := []byte{0, 0, 0, 5, 65, 108, 105, 99, 101}
	ptyVInfo := []byte{0, 0, 0, 3, 66, 111, 98}

	supPubInfo := []byte{0, 0, 0, 128}

	var supPrivInfo []byte

	expected := []byte{
		86, 170, 141, 234, 248, 35, 109, 32, 92, 34, 40, 205, 113, 167, 16, 26,
	}

	out := internal.ConcatKDF(crypto.SHA256, z, 16, algID, ptyUInfo, ptyVInfo, supPubInfo, supPrivInfo)
	require.Equal(t, expected, out)
}
