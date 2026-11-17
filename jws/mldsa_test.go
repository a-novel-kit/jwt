package jws_test

import (
	"crypto/mldsa"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt/v2"
	"github.com/a-novel-kit/jwt/v2/jwa"
	"github.com/a-novel-kit/jwt/v2/jwk"
	"github.com/a-novel-kit/jwt/v2/jwk/serializers"
	"github.com/a-novel-kit/jwt/v2/jws"
)

func TestMLDSAVerifier(t *testing.T) {
	t.Parallel()

	// A key's parameter set fixes the one algorithm it verifies.
	t.Run("Error/OtherLevel", func(t *testing.T) {
		t.Parallel()

		_, publicKey, err := jwk.GenerateMLDSA(jwk.MLDSA44)
		require.NoError(t, err)

		_, err = jws.NewMLDSAVerifier(publicKey.Key()).Transform(
			t.Context(), &jwa.JWH{JWHCommon: jwa.JWHCommon{Alg: jwa.MLDSA65}}, "header.payload.signature",
		)
		require.ErrorIs(t, err, jwt.ErrMismatchRecipientPlugin)
	})

	// RFC 9964 Appendix A.1 derives its key from the all-zero seed and signs a text payload with it.
	// Decoding the key checks the seed expands to the published public key; verifying the token checks
	// the signature encoding other implementations produce.
	t.Run("Success/RFC9964Vector", func(t *testing.T) {
		t.Parallel()

		var vector struct {
			JWK serializers.MLDSAPayload `json:"jwk"`
			JWS string                   `json:"jws"`
		}

		readVector(t, "rfc9964-mldsa44.json", &vector)

		_, publicKey, err := serializers.DecodeMLDSA(&vector.JWK, mldsa.MLDSA44())
		require.NoError(t, err)

		payload, err := jws.NewMLDSAVerifier(publicKey).Transform(
			t.Context(), &jwa.JWH{JWHCommon: jwa.JWHCommon{Alg: jwa.MLDSA44}}, vector.JWS,
		)
		require.NoError(t, err)
		require.Equal(t, "It’s a dangerous business, Frodo, going out your door.", string(payload))
	})
}

func TestSourcedMLDSASigner(t *testing.T) {
	t.Parallel()

	// Without a key ID, the signer takes the first ML-DSA key whatever its level, and labels the token
	// with that key's algorithm.
	t.Run("Success/FirstKeyOfAnyLevel", func(t *testing.T) {
		t.Parallel()

		first, second := mldsaCase(jwk.MLDSA65).newKeys(), mldsaCase(jwk.MLDSA44).newKeys()
		signer := jws.NewSourcedMLDSASigner(newSource(first.signing, second.signing))

		header, err := signer.Header(t.Context(), &jwa.JWH{})
		require.NoError(t, err)
		require.Equal(t, jwa.MLDSA65, header.Alg)

		require.NoError(t, consume(t, first.verifier, issue(t, signer, "")))
	})
}

func TestSourcedMLDSAVerifier(t *testing.T) {
	t.Parallel()

	signing, otherLevel := mldsaCase(jwk.MLDSA44).newKeys(), mldsaCase(jwk.MLDSA65).newKeys()
	token := issue(t, signing.signer, "")

	// A source can hold keys of every level. A key of another level sits in it without stopping the
	// search.
	t.Run("Success/MixedLevels", func(t *testing.T) {
		t.Parallel()

		verifier := jws.NewSourcedMLDSAVerifier(newSource(otherLevel.verification, signing.verification))

		require.NoError(t, consume(t, verifier, token))
	})

	t.Run("Error/OtherAlgorithm", func(t *testing.T) {
		t.Parallel()

		verifier := jws.NewSourcedMLDSAVerifier(newSource(signing.verification))

		_, err := verifier.Transform(t.Context(), &jwa.JWH{JWHCommon: jwa.JWHCommon{Alg: jwa.Ed25519}}, token)
		require.ErrorIs(t, err, jwt.ErrMismatchRecipientPlugin)
	})
}
