package jws_test

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt"
	"github.com/a-novel-kit/jwt/jwk"
	"github.com/a-novel-kit/jwt/jws"
	"github.com/a-novel-kit/jwt/testutils"
)

func TestECDSA(t *testing.T) {
	testCases := []struct {
		name string

		keyPreset jwk.ECDSAPreset
		preset    jws.ECDSAPreset
	}{
		{
			name:      "ES256",
			keyPreset: jwk.ES256,
			preset:    jws.ES256,
		},
		{
			name:      "ES384",
			keyPreset: jwk.ES384,
			preset:    jws.ES384,
		},
		{
			name:      "ES512",
			keyPreset: jwk.ES512,
			preset:    jws.ES512,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			privateKey, publicKey, err := jwk.GenerateECDSA(testCase.keyPreset)
			require.NoError(t, err)

			signer := jws.NewECDSASigner(privateKey.Key(), testCase.preset)
			verifier := jws.NewECDSAVerifier(publicKey.Key(), testCase.preset)

			producer := jwt.NewProducer(jwt.ProducerConfig{
				Plugins: []jwt.ProducerPlugin{signer},
			})
			recipient := jwt.NewRecipient(jwt.RecipientConfig{
				Plugins: []jwt.RecipientPlugin{verifier},
			})

			producerClaims := map[string]any{"foo": "bar"}

			token, err := producer.Issue(context.Background(), producerClaims, nil)
			require.NoError(t, err)

			t.Run("OK", func(t *testing.T) {
				var recipientClaims map[string]any
				require.NoError(t, recipient.Consume(context.Background(), token, &recipientClaims))

				require.Equal(t, producerClaims, recipientClaims)
			})

			t.Run("IncorrectHeader", func(t *testing.T) {
				var recipientClaims map[string]any

				customHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"foo"}`))
				parts := strings.Split(token, ".")
				newToken := strings.Join(append([]string{customHeader}, parts[1:]...), ".")

				err := recipient.Consume(context.Background(), newToken, &recipientClaims)
				require.ErrorIs(t, err, jwt.ErrMismatchRecipientPlugin)
			})

			t.Run("InvalidSignature", func(t *testing.T) {
				otherPrivateKey, _, err := jwk.GenerateECDSA(testCase.keyPreset)
				require.NoError(t, err)
				otherSigner := jws.NewECDSASigner(otherPrivateKey.Key(), testCase.preset)
				otherProducer := jwt.NewProducer(jwt.ProducerConfig{
					Plugins: []jwt.ProducerPlugin{otherSigner},
				})

				otherToken, err := otherProducer.Issue(context.Background(), producerClaims, nil)
				require.NoError(t, err)

				var recipientClaims map[string]any

				err = recipient.Consume(context.Background(), otherToken, &recipientClaims)
				require.ErrorIs(t, err, jws.ErrInvalidSignature)
			})
		})
	}
}

func TestECDSASourcedSigner(t *testing.T) {
	testCases := []struct {
		name string

		keyPreset jwk.ECDSAPreset
		preset    jws.ECDSAPreset
	}{
		{
			name:      "ES256",
			keyPreset: jwk.ES256,
			preset:    jws.ES256,
		},
		{
			name:      "ES384",
			keyPreset: jwk.ES384,
			preset:    jws.ES384,
		},
		{
			name:      "ES512",
			keyPreset: jwk.ES512,
			preset:    jws.ES512,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			privateKeys := make([]*jwk.Key[*ecdsa.PrivateKey], 3)
			publicKeys := make([]*jwk.Key[*ecdsa.PublicKey], 3)

			for i := range privateKeys {
				privateKey, publicKey, err := jwk.GenerateECDSA(testCase.keyPreset)
				require.NoError(t, err)
				privateKeys[i] = privateKey
				publicKeys[i] = publicKey
			}

			source := testutils.NewStaticKeysSource(t, privateKeys)

			signer := jws.NewSourcedECDSASigner(source, testCase.preset)
			producer := jwt.NewProducer(jwt.ProducerConfig{
				Plugins: []jwt.ProducerPlugin{signer},
			})

			producerClaims := map[string]any{"foo": "bar"}
			token, err := producer.Issue(context.Background(), producerClaims, nil)
			require.NoError(t, err)

			// OK.
			t.Run("TryFirstKey", func(t *testing.T) {
				recipient := jwt.NewRecipient(jwt.RecipientConfig{
					Plugins: []jwt.RecipientPlugin{jws.NewECDSAVerifier(publicKeys[0].Key(), testCase.preset)},
				})

				var recipientClaims map[string]any
				require.NoError(t, recipient.Consume(context.Background(), token, &recipientClaims))
				require.Equal(t, producerClaims, recipientClaims)
			})

			// KO.
			t.Run("TrySecondKey", func(t *testing.T) {
				recipient := jwt.NewRecipient(jwt.RecipientConfig{
					Plugins: []jwt.RecipientPlugin{jws.NewECDSAVerifier(publicKeys[1].Key(), testCase.preset)},
				})

				var recipientClaims map[string]any
				require.ErrorIs(
					t,
					recipient.Consume(context.Background(), token, &recipientClaims),
					jws.ErrInvalidSignature,
				)
			})
		})
	}
}

func TestECDSASourcedVerifier(t *testing.T) {
	testCases := []struct {
		name string

		keyPreset jwk.ECDSAPreset
		preset    jws.ECDSAPreset
	}{
		{
			name:      "ES256",
			keyPreset: jwk.ES256,
			preset:    jws.ES256,
		},
		{
			name:      "ES384",
			keyPreset: jwk.ES384,
			preset:    jws.ES384,
		},
		{
			name:      "ES512",
			keyPreset: jwk.ES512,
			preset:    jws.ES512,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			privateKeys := make([]*jwk.Key[*ecdsa.PrivateKey], 3)
			publicKeys := make([]*jwk.Key[*ecdsa.PublicKey], 3)

			for i := range privateKeys {
				privateKey, publicKey, err := jwk.GenerateECDSA(testCase.keyPreset)
				require.NoError(t, err)
				privateKeys[i] = privateKey
				publicKeys[i] = publicKey
			}

			source := testutils.NewStaticKeysSource(t, publicKeys)

			signer := jws.NewECDSASigner(privateKeys[0].Key(), testCase.preset)
			producer := jwt.NewProducer(jwt.ProducerConfig{
				Plugins: []jwt.ProducerPlugin{signer},
			})

			producerClaims := map[string]any{"foo": "bar"}
			token, err := producer.Issue(context.Background(), producerClaims, nil)
			require.NoError(t, err)

			// OK.
			t.Run("SigningKeyFirst", func(t *testing.T) {
				recipient := jwt.NewRecipient(jwt.RecipientConfig{
					Plugins: []jwt.RecipientPlugin{jws.NewSourcedECDSAVerifier(source, testCase.preset)},
				})

				var recipientClaims map[string]any
				require.NoError(t, recipient.Consume(context.Background(), token, &recipientClaims))
				require.Equal(t, producerClaims, recipientClaims)
			})

			// OK.
			t.Run("SigningKeySecond", func(t *testing.T) {
				_, newPublicKey, err := jwk.GenerateECDSA(testCase.keyPreset)
				require.NoError(t, err)

				source = testutils.NewStaticKeysSource(
					t,
					append([]*jwk.Key[*ecdsa.PublicKey]{newPublicKey}, publicKeys...),
				)

				recipient := jwt.NewRecipient(jwt.RecipientConfig{
					Plugins: []jwt.RecipientPlugin{jws.NewSourcedECDSAVerifier(source, testCase.preset)},
				})

				var recipientClaims map[string]any
				require.NoError(t, recipient.Consume(context.Background(), token, &recipientClaims))
				require.Equal(t, producerClaims, recipientClaims)
			})

			// KO.
			t.Run("KeyMissing", func(t *testing.T) {
				_, newPublicKey, err := jwk.GenerateECDSA(testCase.keyPreset)
				require.NoError(t, err)

				source = testutils.NewStaticKeysSource(t, []*jwk.Key[*ecdsa.PublicKey]{newPublicKey})

				recipient := jwt.NewRecipient(jwt.RecipientConfig{
					Plugins: []jwt.RecipientPlugin{jws.NewSourcedECDSAVerifier(source, testCase.preset)},
				})

				var recipientClaims map[string]any
				require.ErrorIs(
					t,
					recipient.Consume(context.Background(), token, &recipientClaims),
					jws.ErrInvalidSignature,
				)
			})
		})
	}
}
