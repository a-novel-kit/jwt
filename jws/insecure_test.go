package jws_test

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt"
	"github.com/a-novel-kit/jwt/jwk"
	"github.com/a-novel-kit/jwt/jws"
)

func TestInsecure(t *testing.T) {
	t.Parallel()

	privateKey, _, err := jwk.GenerateED25519()
	require.NoError(t, err)

	signer := jws.NewED25519Signer(privateKey.Key())
	verifier := jws.NewInsecureVerifier()

	producer := jwt.NewProducer(jwt.ProducerConfig{
		Plugins: []jwt.ProducerPlugin{signer},
	})
	recipient := jwt.NewRecipient(jwt.RecipientConfig{
		Plugins: []jwt.RecipientPlugin{verifier},
	})

	producerClaims := map[string]any{"foo": "bar"}

	token, err := producer.Issue(t.Context(), producerClaims, nil)
	require.NoError(t, err)

	t.Run("ValidSignature", func(t *testing.T) {
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

		require.NoError(t, recipient.Consume(t.Context(), newToken, &recipientClaims))
		require.Equal(t, producerClaims, recipientClaims)
	})

	t.Run("InvalidSignature", func(t *testing.T) {
		t.Parallel()

		otherPrivateKey, _, err := jwk.GenerateED25519()
		require.NoError(t, err)

		otherSigner := jws.NewED25519Signer(otherPrivateKey.Key())
		otherProducer := jwt.NewProducer(jwt.ProducerConfig{
			Plugins: []jwt.ProducerPlugin{otherSigner},
		})

		otherToken, err := otherProducer.Issue(t.Context(), producerClaims, nil)
		require.NoError(t, err)

		var recipientClaims map[string]any

		require.NoError(t, recipient.Consume(t.Context(), otherToken, &recipientClaims))
		require.Equal(t, producerClaims, recipientClaims)
	})
}
