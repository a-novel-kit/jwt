package jws_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt/v2"
	"github.com/a-novel-kit/jwt/v2/jwa"
	"github.com/a-novel-kit/jwt/v2/jwk"
	"github.com/a-novel-kit/jwt/v2/jws"
	"github.com/a-novel-kit/jwt/v2/testutils"
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

	t.Run("MalformedSignature", func(t *testing.T) {
		t.Parallel()

		var recipientClaims map[string]any

		parts := strings.Split(token, ".")
		newToken := strings.Join(append(parts[:2:2], testutils.UndecodableSegment), ".")

		err := recipient.Consume(t.Context(), newToken, &recipientClaims)
		require.ErrorIs(t, err, jwt.ErrUnsupportedTokenFormat)
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

	t.Run("Header", func(t *testing.T) {
		t.Parallel()

		header, err := jws.NewED25519Signer(privateKey.Key()).Header(t.Context(), &jwa.JWH{})
		require.NoError(t, err)
		require.Equal(t, jwa.Ed25519, header.Alg)
	})

	// A peer that verifies only "EdDSA" keeps working while this service signs with the legacy label.
	t.Run("LegacyEdDSALabel", func(t *testing.T) {
		t.Parallel()

		legacySigner := jws.NewEdDSASigner(privateKey.Key())

		header, err := legacySigner.Header(t.Context(), &jwa.JWH{})
		require.NoError(t, err)
		require.Equal(t, jwa.EdDSA, header.Alg) //nolint:staticcheck // The legacy label is the expected output.

		legacyToken, err := jwt.NewProducer(jwt.ProducerConfig{Plugins: []jwt.ProducerPlugin{legacySigner}}).
			Issue(t.Context(), producerClaims, nil)
		require.NoError(t, err)

		var recipientClaims map[string]any

		require.NoError(t, recipient.Consume(t.Context(), legacyToken, &recipientClaims))
		require.Equal(t, producerClaims, recipientClaims)
	})

	// RFC 8037 Appendix A.4 signs under the "EdDSA" label RFC 9864 deprecates. Verifying it pins both
	// interoperability and the acceptance of tokens issued before the fully-specified identifier.
	t.Run("RFC8037Vector", func(t *testing.T) {
		t.Parallel()

		rfcPublicKey, err := base64.RawURLEncoding.DecodeString("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo")
		require.NoError(t, err)

		payload, err := jws.NewED25519Verifier(rfcPublicKey).Transform(
			t.Context(),
			&jwa.JWH{JWHCommon: jwa.JWHCommon{Alg: jwa.EdDSA}}, //nolint:staticcheck // The vector predates RFC 9864.
			"eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc."+
				"hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg",
		)
		require.NoError(t, err)
		require.Equal(t, "Example of Ed25519 signing", string(payload))
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

	t.Run("TryFirstKey", func(t *testing.T) {
		t.Parallel()

		recipient := jwt.NewRecipient(jwt.RecipientConfig{
			Plugins: []jwt.RecipientPlugin{jws.NewED25519Verifier(publicKeys[0].Key())},
		})

		var recipientClaims map[string]any

		require.NoError(t, recipient.Consume(t.Context(), token, &recipientClaims))
		require.Equal(t, producerClaims, recipientClaims)
	})

	t.Run("LegacyEdDSALabel", func(t *testing.T) {
		t.Parallel()

		legacySigner := jws.NewSourcedEdDSASigner(source)

		header, err := legacySigner.Header(t.Context(), &jwa.JWH{})
		require.NoError(t, err)
		require.Equal(t, jwa.EdDSA, header.Alg) //nolint:staticcheck // The legacy label is the expected output.
	})

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

	t.Run("SigningKeyFirst", func(t *testing.T) {
		t.Parallel()

		recipient := jwt.NewRecipient(jwt.RecipientConfig{
			Plugins: []jwt.RecipientPlugin{jws.NewSourcedED25519Verifier(source)},
		})

		var recipientClaims map[string]any

		require.NoError(t, recipient.Consume(t.Context(), token, &recipientClaims))
		require.Equal(t, producerClaims, recipientClaims)
	})

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
