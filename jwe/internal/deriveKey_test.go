package internal_test

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt/v2/jwe/internal"
)

// TestVectorDerive runs the worked example of TestVectorConcatKDF one layer up.
//
// TestVectorConcatKDF passes the length-prefixed OtherInfo blocks as literals, so it covers the KDF
// alone. Derive builds those blocks from apu and apv, and it decodes their base64url header values
// first. The appendix carries "apu":"QWxpY2U" in the header, and PartyUInfo holds the bytes of
// "Alice": [65, 108, 105, 99, 101].
//
// https://datatracker.ietf.org/doc/html/rfc7518#appendix-C
func TestVectorDerive(t *testing.T) {
	t.Parallel()

	z := []byte{
		158, 86, 217, 29, 129, 113, 53, 211, 114, 131, 66, 131, 191, 132,
		38, 156, 251, 49, 110, 163, 218, 128, 106, 72, 246, 218, 167, 121,
		140, 254, 144, 196,
	}

	expected := []byte{
		86, 170, 141, 234, 248, 35, 109, 32, 92, 34, 40, 205, 113, 167, 16, 26,
	}

	// The header values the appendix lists, decoded as a caller must decode them.
	apu, err := base64.RawURLEncoding.DecodeString("QWxpY2U")
	require.NoError(t, err)
	require.Equal(t, "Alice", string(apu))

	apv, err := base64.RawURLEncoding.DecodeString("Qm9i")
	require.NoError(t, err)
	require.Equal(t, "Bob", string(apv))

	out, err := internal.Derive(z, "A128GCM", 16, apu, apv)
	require.NoError(t, err)
	require.Equal(t, expected, out)

	require.Equal(t, "VqqN6vgjbSBcIijNcacQGg", base64.RawURLEncoding.EncodeToString(out),
		"the appendix states this base64url form of the derived key")
}

func TestDeriveRejectsTheEncodedAgreementInfo(t *testing.T) {
	t.Parallel()

	// Passing the header field through undecoded is the mistake this vector exists to catch. It
	// derives a key silently, so nothing but a known answer distinguishes it.
	z := []byte{
		158, 86, 217, 29, 129, 113, 53, 211, 114, 131, 66, 131, 191, 132,
		38, 156, 251, 49, 110, 163, 218, 128, 106, 72, 246, 218, 167, 121,
		140, 254, 144, 196,
	}

	correct, err := internal.Derive(z, "A128GCM", 16, []byte("Alice"), []byte("Bob"))
	require.NoError(t, err)

	encoded, err := internal.Derive(z, "A128GCM", 16, []byte("QWxpY2U"), []byte("Qm9i"))
	require.NoError(t, err)

	require.NotEqual(t, correct, encoded)
}
