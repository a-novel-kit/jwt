package jws_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt"
	"github.com/a-novel-kit/jwt/jwk"
	"github.com/a-novel-kit/jwt/jws"
	"github.com/a-novel-kit/jwt/testutils"
)

func TestED25519(t *testing.T) {
	t.Parallel()

	privateKey, publicKey, err := jwk.GenerateED25519()
	require.NoError(t, err)

	signer := jws.NewED25519Signer(privateKey.Key())
	verifier := jws.NewED25519Verifier(publicKey.Key())

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

		otherPrivateKey, _, err := jwk.GenerateED25519()
		require.NoError(t, err)

		otherSigner := jws.NewED25519Signer(otherPrivateKey.Key())
		otherProducer := jwt.NewProducer(jwt.ProducerConfig{
			Plugins: []jwt.ProducerPlugin{otherSigner},
		})

		otherToken, err := otherProducer.Issue(t.Context(), producerClaims, nil)
		require.NoError(t, err)

		var recipientClaims map[string]any

		err = recipient.Consume(t.Context(), otherToken, &recipientClaims)
		require.ErrorIs(t, err, jws.ErrInvalidSignature)
	})
}

func TestED25519SourcedSigner(t *testing.T) {
	t.Parallel()

	privateKeys := make([]*jwk.Key[ed25519.PrivateKey], 3)
	publicKeys := make([]*jwk.Key[ed25519.PublicKey], 3)

	for i := range privateKeys {
		privateKey, publicKey, err := jwk.GenerateED25519()
		require.NoError(t, err)

		privateKeys[i] = privateKey
		publicKeys[i] = publicKey
	}

	source := testutils.NewStaticKeysSource(t, privateKeys)

	signer := jws.NewSourcedED25519Signer(source)
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
			Plugins: []jwt.RecipientPlugin{jws.NewED25519Verifier(publicKeys[0].Key())},
		})

		var recipientClaims map[string]any

		require.NoError(t, recipient.Consume(t.Context(), token, &recipientClaims))
		require.Equal(t, producerClaims, recipientClaims)
	})

	// KO.
	t.Run("TrySecondKey", func(t *testing.T) {
		t.Parallel()

		recipient := jwt.NewRecipient(jwt.RecipientConfig{
			Plugins: []jwt.RecipientPlugin{jws.NewED25519Verifier(publicKeys[1].Key())},
		})

		var recipientClaims map[string]any

		require.ErrorIs(
			t,
			recipient.Consume(t.Context(), token, &recipientClaims),
			jws.ErrInvalidSignature,
		)
	})
}

func TestED25519SourcedVerifier(t *testing.T) {
	t.Parallel()

	privateKeys := make([]*jwk.Key[ed25519.PrivateKey], 3)
	publicKeys := make([]*jwk.Key[ed25519.PublicKey], 3)

	for i := range privateKeys {
		privateKey, publicKey, err := jwk.GenerateED25519()
		require.NoError(t, err)

		privateKeys[i] = privateKey
		publicKeys[i] = publicKey
	}

	source := testutils.NewStaticKeysSource(t, publicKeys)

	signer := jws.NewED25519Signer(privateKeys[0].Key())
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
			Plugins: []jwt.RecipientPlugin{jws.NewSourcedED25519Verifier(source)},
		})

		var recipientClaims map[string]any

		require.NoError(t, recipient.Consume(t.Context(), token, &recipientClaims))
		require.Equal(t, producerClaims, recipientClaims)
	})

	// OK.
	t.Run("SigningKeySecond", func(t *testing.T) {
		t.Parallel()

		_, newPublicKey, err := jwk.GenerateED25519()
		require.NoError(t, err)

		source = testutils.NewStaticKeysSource(
			t,
			append([]*jwk.Key[ed25519.PublicKey]{newPublicKey}, publicKeys...),
		)

		recipient := jwt.NewRecipient(jwt.RecipientConfig{
			Plugins: []jwt.RecipientPlugin{jws.NewSourcedED25519Verifier(source)},
		})

		var recipientClaims map[string]any

		require.NoError(t, recipient.Consume(t.Context(), token, &recipientClaims))
		require.Equal(t, producerClaims, recipientClaims)
	})

	// KO.
	t.Run("KeyMissing", func(t *testing.T) {
		t.Parallel()

		_, newPublicKey, err := jwk.GenerateED25519()
		require.NoError(t, err)

		source = testutils.NewStaticKeysSource(t, []*jwk.Key[ed25519.PublicKey]{newPublicKey})

		recipient := jwt.NewRecipient(jwt.RecipientConfig{
			Plugins: []jwt.RecipientPlugin{jws.NewSourcedED25519Verifier(source)},
		})

		var recipientClaims map[string]any

		require.ErrorIs(
			t,
			recipient.Consume(t.Context(), token, &recipientClaims),
			jws.ErrInvalidSignature,
		)
	})
}
