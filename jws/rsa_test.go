package jws_test

import (
	"crypto"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt/v2"
	"github.com/a-novel-kit/jwt/v2/jwa"
	"github.com/a-novel-kit/jwt/v2/jwk"
	"github.com/a-novel-kit/jwt/v2/jws"
)

func TestRSASigner(t *testing.T) {
	t.Parallel()

	privateKey, _, err := jwk.GenerateRSA(jwk.RS256)
	require.NoError(t, err)

	// A hand-built preset whose algorithm is neither RS* nor PS* fails at signing.
	t.Run("Error/UnsupportedAlgorithm", func(t *testing.T) {
		t.Parallel()

		signer := jws.NewRSASigner(privateKey.Key(), jws.RSAPreset{Hash: crypto.SHA256, Alg: jwa.Alg("RS999")})

		_, err := jwt.NewProducer(jwt.ProducerConfig{Plugins: []jwt.ProducerPlugin{signer}}).
			Issue(t.Context(), testClaims, nil)
		require.ErrorIs(t, err, jws.ErrUnsupportedAlgorithm)
	})
}

func TestRSAVerifier(t *testing.T) {
	t.Parallel()

	privateKey, publicKey, err := jwk.GenerateRSA(jwk.RS256)
	require.NoError(t, err)

	// RS* and PS* share keys, and each verifier is pinned to its preset's alg, so a PKCS1v15 token
	// never reaches a PSS verifier, nor the reverse.
	testCases := []struct {
		name string

		signedWith   jws.RSAPreset
		verifiedWith jws.RSAPreset
	}{
		{name: "Error/PSSVerifierOnPKCS1Token", signedWith: jws.RS256, verifiedWith: jws.PS256},
		{name: "Error/PKCS1VerifierOnPSSToken", signedWith: jws.PS256, verifiedWith: jws.RS256},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			token := issue(t, jws.NewRSASigner(privateKey.Key(), testCase.signedWith), "")
			verifier := jws.NewRSAVerifier(publicKey.Key(), testCase.verifiedWith)

			require.ErrorIs(t, consume(t, verifier, token), jwt.ErrMismatchRecipientPlugin)
		})
	}
}
