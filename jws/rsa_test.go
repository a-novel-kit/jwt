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

func TestRSA(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string

		keyPreset jwk.RSAPreset
		preset    jws.RSAPreset
	}{
		{
			name:      "ES256",
			keyPreset: jwk.RS256,
			preset:    jws.RS256,
		},
		{
			name:      "ES384",
			keyPreset: jwk.RS384,
			preset:    jws.RS384,
		},
		{
			name:      "ES512",
			keyPreset: jwk.RS512,
			preset:    jws.RS512,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			privateKey, publicKey, err := jwk.GenerateRSA(testCase.keyPreset)
			require.NoError(t, err)

			signer := jws.NewRSASigner(privateKey.Key(), testCase.preset)
			verifier := jws.NewRSAVerifier(publicKey.Key(), testCase.preset)

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

				otherSigner := jws.NewRSASigner(otherPrivateKey.Key(), testCase.preset)
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

func TestRSASourcedSigner(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string

		keyPreset jwk.RSAPreset
		preset    jws.RSAPreset
	}{
		{
			name:      "RS256",
			keyPreset: jwk.RS256,
			preset:    jws.RS256,
		},
		{
			name:      "RS384",
			keyPreset: jwk.RS384,
			preset:    jws.RS384,
		},
		{
			name:      "RS512",
			keyPreset: jwk.RS512,
			preset:    jws.RS512,
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

			signer := jws.NewSourcedRSASigner(source, testCase.preset)
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
					Plugins: []jwt.RecipientPlugin{jws.NewRSAVerifier(publicKeys[0].Key(), testCase.preset)},
				})

				var recipientClaims map[string]any

				require.NoError(t, recipient.Consume(t.Context(), token, &recipientClaims))
				require.Equal(t, producerClaims, recipientClaims)
			})

			// KO.
			t.Run("TrySecondKey", func(t *testing.T) {
				t.Parallel()

				recipient := jwt.NewRecipient(jwt.RecipientConfig{
					Plugins: []jwt.RecipientPlugin{jws.NewRSAVerifier(publicKeys[1].Key(), testCase.preset)},
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

func TestRSASourcedVerifier(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string

		keyPreset jwk.RSAPreset
		preset    jws.RSAPreset
	}{
		{
			name:      "RS256",
			keyPreset: jwk.RS256,
			preset:    jws.RS256,
		},
		{
			name:      "RS384",
			keyPreset: jwk.RS384,
			preset:    jws.RS384,
		},
		{
			name:      "RS512",
			keyPreset: jwk.RS512,
			preset:    jws.RS512,
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

			signer := jws.NewRSASigner(privateKeys[0].Key(), testCase.preset)
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
					Plugins: []jwt.RecipientPlugin{jws.NewSourcedRSAVerifier(source, testCase.preset)},
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
					Plugins: []jwt.RecipientPlugin{jws.NewSourcedRSAVerifier(source, testCase.preset)},
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
					Plugins: []jwt.RecipientPlugin{jws.NewSourcedRSAVerifier(source, testCase.preset)},
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
