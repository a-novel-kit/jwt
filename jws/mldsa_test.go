package jws_test

import (
	"crypto/mldsa"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt/v2"
	"github.com/a-novel-kit/jwt/v2/jwa"
	"github.com/a-novel-kit/jwt/v2/jwk"
	"github.com/a-novel-kit/jwt/v2/jwk/serializers"
	"github.com/a-novel-kit/jwt/v2/jws"
	"github.com/a-novel-kit/jwt/v2/testutils"
)

func TestMLDSA(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string

		preset jwk.MLDSAPreset
	}{
		{name: "MLDSA44", preset: jwk.MLDSA44},
		{name: "MLDSA65", preset: jwk.MLDSA65},
		{name: "MLDSA87", preset: jwk.MLDSA87},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			privateKey, publicKey, err := jwk.GenerateMLDSA(testCase.preset)
			require.NoError(t, err)

			producer := jwt.NewProducer(jwt.ProducerConfig{
				Plugins: []jwt.ProducerPlugin{jws.NewMLDSASigner(privateKey.Key())},
			})
			recipient := jwt.NewRecipient(jwt.RecipientConfig{
				Plugins: []jwt.RecipientPlugin{jws.NewMLDSAVerifier(publicKey.Key())},
			})

			producerClaims := map[string]any{"foo": "bar"}

			token, err := producer.Issue(t.Context(), producerClaims, nil)
			require.NoError(t, err)

			t.Run("OK", func(t *testing.T) {
				t.Parallel()

				var recipientClaims map[string]any

				require.NoError(t, recipient.Consume(t.Context(), token, &recipientClaims))
				require.Equal(t, producerClaims, recipientClaims)
			})

			t.Run("Header", func(t *testing.T) {
				t.Parallel()

				header, err := jws.NewMLDSASigner(privateKey.Key()).Header(t.Context(), &jwa.JWH{})
				require.NoError(t, err)
				require.Equal(t, testCase.preset.Alg, header.Alg)
			})

			t.Run("InvalidSignature", func(t *testing.T) {
				t.Parallel()

				otherPrivateKey, _, err := jwk.GenerateMLDSA(testCase.preset)
				require.NoError(t, err)

				otherProducer := jwt.NewProducer(jwt.ProducerConfig{
					Plugins: []jwt.ProducerPlugin{jws.NewMLDSASigner(otherPrivateKey.Key())},
				})

				otherToken, err := otherProducer.Issue(t.Context(), producerClaims, nil)
				require.NoError(t, err)

				var recipientClaims map[string]any

				err = recipient.Consume(t.Context(), otherToken, &recipientClaims)
				require.ErrorIs(t, err, jws.ErrInvalidSignature)
			})
		})
	}

	t.Run("Error/OtherLevel", func(t *testing.T) {
		t.Parallel()

		_, publicKey, err := jwk.GenerateMLDSA(jwk.MLDSA44)
		require.NoError(t, err)

		_, err = jws.NewMLDSAVerifier(publicKey.Key()).Transform(
			t.Context(), &jwa.JWH{JWHCommon: jwa.JWHCommon{Alg: jwa.MLDSA65}}, "a.b.c",
		)
		require.ErrorIs(t, err, jwt.ErrMismatchRecipientPlugin)
	})

	t.Run("Error/NilKey", func(t *testing.T) {
		t.Parallel()

		_, err := jws.NewMLDSASigner(nil).Header(t.Context(), &jwa.JWH{})
		require.ErrorIs(t, err, jwt.ErrInvalidSecretKey)

		_, err = jws.NewMLDSAVerifier(nil).Transform(
			t.Context(), &jwa.JWH{JWHCommon: jwa.JWHCommon{Alg: jwa.MLDSA44}}, "a.b.c",
		)
		require.ErrorIs(t, err, jwt.ErrInvalidSecretKey)
	})

	// RFC 9964 Appendix A.1 derives its key from the all-zero seed and signs a text payload with it.
	// Decoding the key checks the seed expands to the published public key; verifying the token checks
	// the signature encoding other implementations produce.
	t.Run("RFC9964Vector", func(t *testing.T) {
		t.Parallel()

		raw, err := os.ReadFile("testdata/rfc9964-mldsa44.json")
		require.NoError(t, err)

		var vector struct {
			JWK serializers.MLDSAPayload `json:"jwk"`
			JWS string                   `json:"jws"`
		}

		require.NoError(t, json.Unmarshal(raw, &vector))

		_, publicKey, err := serializers.DecodeMLDSA(&vector.JWK, mldsa.MLDSA44())
		require.NoError(t, err)

		payload, err := jws.NewMLDSAVerifier(publicKey).Transform(
			t.Context(), &jwa.JWH{JWHCommon: jwa.JWHCommon{Alg: jwa.MLDSA44}}, vector.JWS,
		)
		require.NoError(t, err)
		require.Equal(t, "It’s a dangerous business, Frodo, going out your door.", string(payload))
	})
}

func TestMLDSASourcedSigner(t *testing.T) {
	t.Parallel()

	firstPrivateKey, firstPublicKey, err := jwk.GenerateMLDSA(jwk.MLDSA65)
	require.NoError(t, err)

	secondPrivateKey, secondPublicKey, err := jwk.GenerateMLDSA(jwk.MLDSA44)
	require.NoError(t, err)

	source := testutils.NewStaticKeysSource(t, []*jwk.Key[*mldsa.PrivateKey]{firstPrivateKey, secondPrivateKey})

	producer := jwt.NewProducer(jwt.ProducerConfig{
		Plugins: []jwt.ProducerPlugin{jws.NewSourcedMLDSASigner(source)},
	})

	producerClaims := map[string]any{"foo": "bar"}

	token, err := producer.Issue(t.Context(), producerClaims, nil)
	require.NoError(t, err)

	t.Run("TryFirstKey", func(t *testing.T) {
		t.Parallel()

		recipient := jwt.NewRecipient(jwt.RecipientConfig{
			Plugins: []jwt.RecipientPlugin{jws.NewMLDSAVerifier(firstPublicKey.Key())},
		})

		var recipientClaims map[string]any

		require.NoError(t, recipient.Consume(t.Context(), token, &recipientClaims))
		require.Equal(t, producerClaims, recipientClaims)
	})

	// A private key labeled for verification decodes like any other, so only its key_ops keep a signer
	// from using it.
	t.Run("Error/VerifyOnlyPrivateKey", func(t *testing.T) {
		t.Parallel()

		verifyOnly := withKeyOps(t, firstPrivateKey, jwa.KeyOpVerify)
		signer := jws.NewSourcedMLDSASigner(testutils.NewStaticKeysSource(t, []*jwk.Key[*mldsa.PrivateKey]{verifyOnly}))

		_, err := signer.Header(t.Context(), &jwa.JWH{})
		require.ErrorIs(t, err, jwk.ErrKeyNotFound)

		_, err = signer.Header(t.Context(), &jwa.JWH{JWHCommon: jwa.JWHCommon{
			JWHEmbeddedKey: jwa.JWHEmbeddedKey{KID: verifyOnly.KID},
		}})
		require.ErrorIs(t, err, jwk.ErrJWKMismatch)
	})

	t.Run("TrySecondKey", func(t *testing.T) {
		t.Parallel()

		recipient := jwt.NewRecipient(jwt.RecipientConfig{
			Plugins: []jwt.RecipientPlugin{jws.NewMLDSAVerifier(secondPublicKey.Key())},
		})

		var recipientClaims map[string]any

		require.ErrorIs(
			t,
			recipient.Consume(t.Context(), token, &recipientClaims),
			jwt.ErrMismatchRecipientPlugin,
		)
	})
}

func TestMLDSASourcedVerifier(t *testing.T) {
	t.Parallel()

	privateKey, publicKey, err := jwk.GenerateMLDSA(jwk.MLDSA44)
	require.NoError(t, err)

	_, otherLevelKey, err := jwk.GenerateMLDSA(jwk.MLDSA65)
	require.NoError(t, err)

	_, otherKey, err := jwk.GenerateMLDSA(jwk.MLDSA44)
	require.NoError(t, err)

	producer := jwt.NewProducer(jwt.ProducerConfig{
		Plugins: []jwt.ProducerPlugin{jws.NewMLDSASigner(privateKey.Key())},
	})

	producerClaims := map[string]any{"foo": "bar"}

	token, err := producer.Issue(t.Context(), producerClaims, nil)
	require.NoError(t, err)

	testCases := []struct {
		name string

		keys []*jwk.Key[*mldsa.PublicKey]

		expectErr error
	}{
		{name: "SigningKeyFirst", keys: []*jwk.Key[*mldsa.PublicKey]{publicKey, otherKey}},
		{name: "SigningKeySecond", keys: []*jwk.Key[*mldsa.PublicKey]{otherKey, publicKey}},
		// A key of another level sits in the source without stopping the search.
		{name: "MixedLevels", keys: []*jwk.Key[*mldsa.PublicKey]{otherLevelKey, publicKey}},
		{name: "KeyMissing", keys: []*jwk.Key[*mldsa.PublicKey]{otherLevelKey, otherKey}, expectErr: jws.ErrInvalidSignature},
		{
			name:      "SignOnlyKey",
			keys:      []*jwk.Key[*mldsa.PublicKey]{withKeyOps(t, publicKey, jwa.KeyOpSign)},
			expectErr: jws.ErrInvalidSignature,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			recipient := jwt.NewRecipient(jwt.RecipientConfig{
				Plugins: []jwt.RecipientPlugin{
					jws.NewSourcedMLDSAVerifier(testutils.NewStaticKeysSource(t, testCase.keys)),
				},
			})

			var recipientClaims map[string]any

			err := recipient.Consume(t.Context(), token, &recipientClaims)
			require.ErrorIs(t, err, testCase.expectErr)

			if err == nil {
				require.Equal(t, producerClaims, recipientClaims)
			}
		})
	}

	t.Run("Error/OtherAlgorithm", func(t *testing.T) {
		t.Parallel()

		_, err := jws.NewSourcedMLDSAVerifier(testutils.NewStaticKeysSource(t, []*jwk.Key[*mldsa.PublicKey]{publicKey})).
			Transform(t.Context(), &jwa.JWH{JWHCommon: jwa.JWHCommon{Alg: jwa.Ed25519}}, token)
		require.ErrorIs(t, err, jwt.ErrMismatchRecipientPlugin)
	})
}

// withKeyOps returns a copy of key whose JWK lists only ops, leaving the key material untouched.
func withKeyOps[K any](t *testing.T, key *jwk.Key[K], ops ...jwa.KeyOp) *jwk.Key[K] {
	t.Helper()

	relabeled := *key.JWK
	relabeled.KeyOps = ops

	return jwk.NewKey(&relabeled, key.Key())
}
