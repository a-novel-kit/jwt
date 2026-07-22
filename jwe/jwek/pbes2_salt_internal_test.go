package jwek

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt/v2/jwa"
)

// RFC 7518 §4.8.1.1: "The salt value used is (UTF8(Alg) || 0x00 || Salt Input), where Alg is the
// 'alg' (algorithm) Header Parameter value."
//
// Salt Input is the base64url-decoded p2s. This asserts the construction against that rule
// directly: encrypt and decrypt share whatever salt the code builds, so a round-trip test passes on
// any value and only a foreign implementation would have noticed.
func TestPBES2SaltFollowsTheSpecifiedConstruction(t *testing.T) {
	t.Parallel()

	const p2s = "2WCTcJZ1Rvd_CJuJripQ1w"

	saltInput, err := base64.RawURLEncoding.DecodeString(p2s)
	require.NoError(t, err)

	got, err := pbes2Salt(jwa.PBES2HS256A128KW, p2s)
	require.NoError(t, err)

	// Built here from the quoted rule, independently of the implementation.
	want := append(append([]byte(jwa.PBES2HS256A128KW), 0x00), saltInput...)
	require.Equal(t, want, got)

	// The two values a reader most easily reaches for instead.
	require.NotEqual(t, []byte(p2s), got, "the encoded p2s text is not the salt")
	require.NotEqual(t, saltInput, got, "the salt input alone omits the mandatory algorithm prefix")

	// The prefix is what separates one algorithm's derivation from another's, so the same salt
	// input under a different alg must not produce the same salt.
	other, err := pbes2Salt(jwa.PBES2HS512A256KW, p2s)
	require.NoError(t, err)
	require.NotEqual(t, got, other)
}

func TestPBES2SaltRejectsAMalformedP2S(t *testing.T) {
	t.Parallel()

	_, err := pbes2Salt(jwa.PBES2HS256A128KW, "not valid base64!!")
	require.Error(t, err)
}
