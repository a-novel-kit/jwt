package jws_test

import (
	"crypto/rsa"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt"
	"github.com/a-novel-kit/jwt/jwk"
	"github.com/a-novel-kit/jwt/jws"
	"github.com/a-novel-kit/jwt/testutils"
)

func TestRSAPSS(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string

		keyPreset jwk.RSAPreset
		preset    jws.RSAPSSPreset
	}{
		{
			name:      "PS256",
			keyPreset: jwk.PS256,
			preset:    jws.PS256,
		},
		{
			name:      "PS384",
			keyPreset: jwk.PS384,
			preset:    jws.PS384,
		},
		{
			name:      "PS512",
			keyPreset: jwk.PS512,
			preset:    jws.PS512,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			privateKey, publicKey, err := jwk.GenerateRSA(testCase.keyPreset)
			require.NoError(t, err)

			signer := jws.NewRSAPSSSigner(privateKey.Key(), testCase.preset)
			verifier := jws.NewRSAPSSVerifier(publicKey.Key(), testCase.preset)

			producer := jwt.NewProducer(jwt.ProducerConfig{
				Plugins: []jwt.ProducerPlugin{signer},
			})
			recipient := jwt.NewRecipient(jwt.RecipientConfig{
				Plugins: []jwt.RecipientPlugin{verifier},
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

			t.Run("IncorrectHeader", func(t *testing.T) {
				t.Parallel()

				var recipientClaims map[string]any

				customHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"foo"}`))
				parts := strings.Split(token, ".")
				newToken := strings.Join(append([]string{customHeader}, parts[1:]...), ".")

				err := recipient.Consume(t.Context(), newToken, &recipientClaims)
				require.ErrorIs(t, err, jwt.ErrMismatchRecipientPlugin)
			})

			t.Run("InvalidSignature", func(t *testing.T) {
				t.Parallel()

				otherPrivateKey, _, err := jwk.GenerateRSA(testCase.keyPreset)
				require.NoError(t, err)

				otherSigner := jws.NewRSAPSSSigner(otherPrivateKey.Key(), testCase.preset)
				otherProducer := jwt.NewProducer(jwt.ProducerConfig{
					Plugins: []jwt.ProducerPlugin{otherSigner},
				})

				otherToken, err := otherProducer.Issue(t.Context(), producerClaims, nil)
				require.NoError(t, err)

				var recipientClaims map[string]any

				err = recipient.Consume(t.Context(), otherToken, &recipientClaims)
				require.ErrorIs(t, err, jws.ErrInvalidSignature)
			})
		})
	}
}

func TestRSAPSSSourcedSigner(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string

		keyPreset jwk.RSAPreset
		preset    jws.RSAPSSPreset
	}{
		{
			name:      "PS256",
			keyPreset: jwk.PS256,
			preset:    jws.PS256,
		},
		{
			name:      "PS384",
			keyPreset: jwk.PS384,
			preset:    jws.PS384,
		},
		{
			name:      "PS512",
			keyPreset: jwk.PS512,
			preset:    jws.PS512,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			privateKeys := make([]*jwk.Key[*rsa.PrivateKey], 3)
			publicKeys := make([]*jwk.Key[*rsa.PublicKey], 3)

			for i := range privateKeys {
				privateKey, publicKey, err := jwk.GenerateRSA(testCase.keyPreset)
				require.NoError(t, err)

				privateKeys[i] = privateKey
				publicKeys[i] = publicKey
			}

			source := testutils.NewStaticKeysSource(t, privateKeys)

			signer := jws.NewSourcedRSAPSSSigner(source, testCase.preset)
			producer := jwt.NewProducer(jwt.ProducerConfig{
				Plugins: []jwt.ProducerPlugin{signer},
			})

			producerClaims := map[string]any{"foo": "bar"}
			token, err := producer.Issue(t.Context(), producerClaims, nil)
			require.NoError(t, err)

			// OK.
			t.Run("TryFirstKey", func(t *testing.T) {
				t.Parallel()

				recipient := jwt.NewRecipient(jwt.RecipientConfig{
					Plugins: []jwt.RecipientPlugin{jws.NewRSAPSSVerifier(publicKeys[0].Key(), testCase.preset)},
				})

				var recipientClaims map[string]any

				require.NoError(t, recipient.Consume(t.Context(), token, &recipientClaims))
				require.Equal(t, producerClaims, recipientClaims)
			})

			// KO.
			t.Run("TrySecondKey", func(t *testing.T) {
				t.Parallel()

				recipient := jwt.NewRecipient(jwt.RecipientConfig{
					Plugins: []jwt.RecipientPlugin{jws.NewRSAPSSVerifier(publicKeys[1].Key(), testCase.preset)},
				})

				var recipientClaims map[string]any

				require.ErrorIs(
					t,
					recipient.Consume(t.Context(), token, &recipientClaims),
					jws.ErrInvalidSignature,
				)
			})
		})
	}
}

func TestRSAPSSSourcedVerifier(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string

		keyPreset jwk.RSAPreset
		preset    jws.RSAPSSPreset
	}{
		{
			name:      "PS256",
			keyPreset: jwk.PS256,
			preset:    jws.PS256,
		},
		{
			name:      "PS384",
			keyPreset: jwk.PS384,
			preset:    jws.PS384,
		},
		{
			name:      "PS512",
			keyPreset: jwk.PS512,
			preset:    jws.PS512,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			privateKeys := make([]*jwk.Key[*rsa.PrivateKey], 3)
			publicKeys := make([]*jwk.Key[*rsa.PublicKey], 3)

			for i := range privateKeys {
				privateKey, publicKey, err := jwk.GenerateRSA(testCase.keyPreset)
				require.NoError(t, err)

				privateKeys[i] = privateKey
				publicKeys[i] = publicKey
			}

			source := testutils.NewStaticKeysSource(t, publicKeys)

			signer := jws.NewRSAPSSSigner(privateKeys[0].Key(), testCase.preset)
			producer := jwt.NewProducer(jwt.ProducerConfig{
				Plugins: []jwt.ProducerPlugin{signer},
			})

			producerClaims := map[string]any{"foo": "bar"}
			token, err := producer.Issue(t.Context(), producerClaims, nil)
			require.NoError(t, err)

			// OK.
			t.Run("SigningKeyFirst", func(t *testing.T) {
				t.Parallel()

				recipient := jwt.NewRecipient(jwt.RecipientConfig{
					Plugins: []jwt.RecipientPlugin{jws.NewSourcedRSAPSSVerifier(source, testCase.preset)},
				})

				var recipientClaims map[string]any

				require.NoError(t, recipient.Consume(t.Context(), token, &recipientClaims))
				require.Equal(t, producerClaims, recipientClaims)
			})

			// OK.
			t.Run("SigningKeySecond", func(t *testing.T) {
				t.Parallel()

				_, newPublicKey, err := jwk.GenerateRSA(testCase.keyPreset)
				require.NoError(t, err)

				source = testutils.NewStaticKeysSource(
					t,
					append([]*jwk.Key[*rsa.PublicKey]{newPublicKey}, publicKeys...),
				)

				recipient := jwt.NewRecipient(jwt.RecipientConfig{
					Plugins: []jwt.RecipientPlugin{jws.NewSourcedRSAPSSVerifier(source, testCase.preset)},
				})

				var recipientClaims map[string]any

				require.NoError(t, recipient.Consume(t.Context(), token, &recipientClaims))
				require.Equal(t, producerClaims, recipientClaims)
			})

			// KO.
			t.Run("KeyMissing", func(t *testing.T) {
				t.Parallel()

				_, newPublicKey, err := jwk.GenerateRSA(testCase.keyPreset)
				require.NoError(t, err)

				source = testutils.NewStaticKeysSource(t, []*jwk.Key[*rsa.PublicKey]{newPublicKey})

				recipient := jwt.NewRecipient(jwt.RecipientConfig{
					Plugins: []jwt.RecipientPlugin{jws.NewSourcedRSAPSSVerifier(source, testCase.preset)},
				})

				var recipientClaims map[string]any

				require.ErrorIs(
					t,
					recipient.Consume(t.Context(), token, &recipientClaims),
					jws.ErrInvalidSignature,
				)
			})
		})
	}
}
