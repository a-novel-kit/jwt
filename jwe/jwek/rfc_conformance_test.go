package jwek_test

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt/v2/jwa"
	"github.com/a-novel-kit/jwt/v2/jwe/jwek"
	"github.com/a-novel-kit/jwt/v2/jwk"
)

// These assert the two encoding rules against the specification text rather than against the
// library's own round trip. Both defects were invisible precisely because producer and consumer
// agreed on the wrong value, so any test that encrypts and then decrypts passes either way.

func TestPBES2AppliesItsDefaults(t *testing.T) {
	t.Parallel()

	// A zero SaltSize used to produce a zero-length salt with no error — rand.Read on an empty
	// slice returns (0, nil) — so every token from one password shared a wrap key. A zero
	// Iterations produced p2c=0, which the decoder rejects, so the token was undecryptable and
	// only the recipient found out.
	manager := jwek.NewPBES2KeyEncKWManager(&jwek.PBES2KeyEncKWManagerConfig{
		Secret: "a password",
		CEK:    make([]byte, 16),
	}, jwek.PBES2A128KW)

	first, err := manager.SetHeader(t.Context(), &jwa.JWH{})
	require.NoError(t, err)

	saltInput, err := base64.RawURLEncoding.DecodeString(first.P2S)
	require.NoError(t, err)
	require.Len(t, saltInput, jwek.DefaultPBES2SaltSize)
	require.Equal(t, jwek.DefaultPBES2Iterations, first.P2C)

	second, err := manager.SetHeader(t.Context(), &jwa.JWH{})
	require.NoError(t, err)
	require.NotEqual(t, first.P2S, second.P2S, "each token must carry a fresh salt")
}

// RFC 7518 §4.6.1.2 and §4.6.1.3 define apu and apv as base64url-encoded values. The header must
// carry the encoded form, and the KDF must mix in the decoded bytes.
func TestECDHAgreementInfoIsEncodedInTheHeader(t *testing.T) {
	t.Parallel()

	const (
		producerInfo  = "Alice"
		recipientInfo = "Bob"
	)

	producerPrivateKey, _, err := jwk.GenerateECDH()
	require.NoError(t, err)

	_, recipientPublicKey, err := jwk.GenerateECDH()
	require.NoError(t, err)

	manager := jwek.NewECDHKeyAgrManager(&jwek.ECDHKeyAgrManagerConfig{
		ProducerKey:   producerPrivateKey.Key(),
		RecipientKey:  recipientPublicKey.Key(),
		ProducerInfo:  producerInfo,
		RecipientInfo: recipientInfo,
	}, jwek.ECDHESA128GCM)

	header, err := manager.SetHeader(t.Context(), &jwa.JWH{})
	require.NoError(t, err)

	require.NotEqual(t, producerInfo, header.APU, "apu travels encoded, not as the raw string")

	decodedAPU, err := base64.RawURLEncoding.DecodeString(header.APU)
	require.NoError(t, err, "apu must be valid base64url")
	require.Equal(t, producerInfo, string(decodedAPU))

	decodedAPV, err := base64.RawURLEncoding.DecodeString(header.APV)
	require.NoError(t, err, "apv must be valid base64url")
	require.Equal(t, recipientInfo, string(decodedAPV))
}
