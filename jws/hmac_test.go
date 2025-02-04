package jws_test

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt"
	"github.com/a-novel-kit/jwt/jwk"
	"github.com/a-novel-kit/jwt/jws"
	"github.com/a-novel-kit/jwt/testutils"
)

func TestHMAC(t *testing.T) {
	testCases := []struct {
		name string

		keyPreset jwk.HMACPreset
		preset    jws.HMACPreset
	}{
		{
			name:      "HS256",
			keyPreset: jwk.HS256,
			preset:    jws.HS256,
		},
		{
			name:      "HS384",
			keyPreset: jwk.HS384,
			preset:    jws.HS384,
		},
		{
			name:      "HS512",
			keyPreset: jwk.HS512,
			preset:    jws.HS512,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			secretKey, err := jwk.GenerateHMAC(testCase.keyPreset)
			require.NoError(t, err)

			signer := jws.NewHMACSigner(secretKey.Key(), testCase.preset)
			verifier := jws.NewHMACVerifier(secretKey.Key(), testCase.preset)

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
				otherPrivateKey, err := jwk.GenerateHMAC(testCase.keyPreset)
				require.NoError(t, err)
				otherSigner := jws.NewHMACSigner(otherPrivateKey.Key(), testCase.preset)
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

func TestHMACSourcedSigner(t *testing.T) {
	testCases := []struct {
		name string

		keyPreset jwk.HMACPreset
		preset    jws.HMACPreset
	}{
		{
			name:      "HS256",
			keyPreset: jwk.HS256,
			preset:    jws.HS256,
		},
		{
			name:      "HS384",
			keyPreset: jwk.HS384,
			preset:    jws.HS384,
		},
		{
			name:      "HS512",
			keyPreset: jwk.HS512,
			preset:    jws.HS512,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			secretKeys := make([]*jwk.Key[[]byte], 3)

			for i := range secretKeys {
				secretKey, err := jwk.GenerateHMAC(testCase.keyPreset)
				require.NoError(t, err)
				secretKeys[i] = secretKey
			}

			source := testutils.NewStaticKeysSource(t, secretKeys)

			signer := jws.NewSourcedHMACSigner(source, testCase.preset)
			producer := jwt.NewProducer(jwt.ProducerConfig{
				Plugins: []jwt.ProducerPlugin{signer},
			})

			producerClaims := map[string]any{"foo": "bar"}
			token, err := producer.Issue(context.Background(), producerClaims, nil)
			require.NoError(t, err)

			// OK.
			t.Run("TryFirstKey", func(t *testing.T) {
				recipient := jwt.NewRecipient(jwt.RecipientConfig{
					Plugins: []jwt.RecipientPlugin{jws.NewHMACVerifier(secretKeys[0].Key(), testCase.preset)},
				})

				var recipientClaims map[string]any
				require.NoError(t, recipient.Consume(context.Background(), token, &recipientClaims))
				require.Equal(t, producerClaims, recipientClaims)
			})

			// KO.
			t.Run("TrySecondKey", func(t *testing.T) {
				recipient := jwt.NewRecipient(jwt.RecipientConfig{
					Plugins: []jwt.RecipientPlugin{jws.NewHMACVerifier(secretKeys[1].Key(), testCase.preset)},
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

func TestHMACSourcedVerifier(t *testing.T) {
	testCases := []struct {
		name string

		keyPreset jwk.HMACPreset
		preset    jws.HMACPreset
	}{
		{
			name:      "HS256",
			keyPreset: jwk.HS256,
			preset:    jws.HS256,
		},
		{
			name:      "HS384",
			keyPreset: jwk.HS384,
			preset:    jws.HS384,
		},
		{
			name:      "HS512",
			keyPreset: jwk.HS512,
			preset:    jws.HS512,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			secretKeys := make([]*jwk.Key[[]byte], 3)

			for i := range secretKeys {
				secretKey, err := jwk.GenerateHMAC(testCase.keyPreset)
				require.NoError(t, err)
				secretKeys[i] = secretKey
			}

			source := testutils.NewStaticKeysSource(t, secretKeys)

			signer := jws.NewHMACSigner(secretKeys[0].Key(), testCase.preset)
			producer := jwt.NewProducer(jwt.ProducerConfig{
				Plugins: []jwt.ProducerPlugin{signer},
			})

			producerClaims := map[string]any{"foo": "bar"}
			token, err := producer.Issue(context.Background(), producerClaims, nil)
			require.NoError(t, err)

			// OK.
			t.Run("SigningKeyFirst", func(t *testing.T) {
				recipient := jwt.NewRecipient(jwt.RecipientConfig{
					Plugins: []jwt.RecipientPlugin{jws.NewSourcedHMACVerifier(source, testCase.preset)},
				})

				var recipientClaims map[string]any
				require.NoError(t, recipient.Consume(context.Background(), token, &recipientClaims))
				require.Equal(t, producerClaims, recipientClaims)
			})

			// OK.
			t.Run("SigningKeySecond", func(t *testing.T) {
				newSecretKey, err := jwk.GenerateHMAC(testCase.keyPreset)
				require.NoError(t, err)

				source = testutils.NewStaticKeysSource(
					t,
					append([]*jwk.Key[[]byte]{newSecretKey}, secretKeys...),
				)

				recipient := jwt.NewRecipient(jwt.RecipientConfig{
					Plugins: []jwt.RecipientPlugin{jws.NewSourcedHMACVerifier(source, testCase.preset)},
				})

				var recipientClaims map[string]any
				require.NoError(t, recipient.Consume(context.Background(), token, &recipientClaims))
				require.Equal(t, producerClaims, recipientClaims)
			})

			// KO.
			t.Run("KeyMissing", func(t *testing.T) {
				newSecretKey, err := jwk.GenerateHMAC(testCase.keyPreset)
				require.NoError(t, err)

				source = testutils.NewStaticKeysSource(t, []*jwk.Key[[]byte]{newSecretKey})

				recipient := jwt.NewRecipient(jwt.RecipientConfig{
					Plugins: []jwt.RecipientPlugin{jws.NewSourcedHMACVerifier(source, testCase.preset)},
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
