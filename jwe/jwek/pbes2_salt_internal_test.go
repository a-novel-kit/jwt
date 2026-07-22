package jwek

import (
	"crypto"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/pbkdf2"

	"github.com/a-novel-kit/jwt/v2/jwa"
)

// RFC 7517 Appendix C works a PBES2 key derivation end to end and states the salt and the derived
// key as octet sequences. Encrypt and decrypt share whatever salt this code builds, so a round trip
// succeeds on any value — a known answer is the only thing that separates a conforming derivation
// from a merely self-consistent one.
//
// https://datatracker.ietf.org/doc/html/rfc7517#appendix-C
func TestVectorPBES2Salt(t *testing.T) {
	t.Parallel()

	// From the JWE Protected Header in C.2.
	const p2s = "2WCTcJZ1Rvd_CJuJripQ1w"

	// C.4: "The Salt value (UTF8(Alg) || 0x00 || Salt Input) is:"
	expectedSalt := []byte{
		80, 66, 69, 83, 50, 45, 72, 83, 50, 53, 54, 43, 65, 49, 50, 56, 75, 87,
		0,
		217, 96, 147, 112, 150, 117, 70, 247, 127, 8, 155, 137, 174, 42, 80, 215,
	}

	salt, err := pbes2Salt(jwa.PBES2HS256A128KW, p2s)
	require.NoError(t, err)
	require.Equal(t, expectedSalt, salt)

	// The two values a reader most easily reaches for instead. Either derives a wrap key no
	// compliant implementation reproduces.
	require.NotEqual(t, []byte(p2s), salt, "the encoded p2s text is not the salt")

	saltInput, err := base64.RawURLEncoding.DecodeString(p2s)
	require.NoError(t, err)
	require.NotEqual(t, saltInput, salt, "the salt input alone omits the mandatory algorithm prefix")
}

func TestVectorPBES2DerivedKey(t *testing.T) {
	t.Parallel()

	// C.4's passphrase, iteration count and 128-bit output size.
	const (
		passphrase = "Thus from my lips, by yours, my sin is purged."
		p2s        = "2WCTcJZ1Rvd_CJuJripQ1w"
		p2c        = 4096
		keySize    = 16
	)

	expectedKey := []byte{110, 171, 169, 92, 129, 92, 109, 117, 233, 242, 116, 233, 170, 14, 24, 75}

	salt, err := pbes2Salt(jwa.PBES2HS256A128KW, p2s)
	require.NoError(t, err)

	got := pbkdf2.Key([]byte(passphrase), salt, p2c, keySize, crypto.SHA256.New)
	require.Equal(t, expectedKey, got)
}

func TestPBES2SaltBindsTheAlgorithm(t *testing.T) {
	t.Parallel()

	// The prefix is what separates one algorithm's derivation from another's, so one password
	// reused across two PBES2 algorithms must not derive related wrap keys.
	const p2s = "2WCTcJZ1Rvd_CJuJripQ1w"

	first, err := pbes2Salt(jwa.PBES2HS256A128KW, p2s)
	require.NoError(t, err)

	second, err := pbes2Salt(jwa.PBES2HS512A256KW, p2s)
	require.NoError(t, err)

	require.NotEqual(t, first, second)
}

func TestPBES2SaltRejectsAMalformedP2S(t *testing.T) {
	t.Parallel()

	_, err := pbes2Salt(jwa.PBES2HS256A128KW, "not valid base64!!")
	require.Error(t, err)
}
