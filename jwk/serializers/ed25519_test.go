package serializers_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt/v2/jwk/serializers"
)

// rfc8037Key is the Ed25519 private key of RFC 8037 Appendix A.1. A round trip agrees with itself on
// any encoding of "d", so only a known answer pins the one other implementations read.
//
// https://datatracker.ietf.org/doc/html/rfc8037#appendix-A.1
var rfc8037Key = serializers.EDPayload{
	Crv: "Ed25519",
	X:   "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
	D:   "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
}

func TestED(t *testing.T) {
	t.Parallel()

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	t.Run("PrivateKey", func(t *testing.T) {
		t.Parallel()

		payload := serializers.EncodeED(privateKey)

		decodedPrivateKey, decodedPublicKey, err := serializers.DecodeED(payload)
		require.NoError(t, err)

		require.True(t, privateKey.Equal(decodedPrivateKey))
		require.True(t, publicKey.Equal(decodedPublicKey))
	})

	t.Run("PublicKey", func(t *testing.T) {
		t.Parallel()

		payload := serializers.EncodeED(publicKey)

		decodedPrivateKey, decodedPublicKey, err := serializers.DecodeED(payload)
		require.NoError(t, err)

		require.Nil(t, decodedPrivateKey)
		require.True(t, publicKey.Equal(decodedPublicKey))
	})

	t.Run("Success/RFC8037Vector", func(t *testing.T) {
		t.Parallel()

		decodedPrivateKey, _, err := serializers.DecodeED(&rfc8037Key)
		require.NoError(t, err)

		require.Equal(t, rfc8037Key, *serializers.EncodeED(decodedPrivateKey))
	})

	t.Run("Success/ExpandedPrivateKey", func(t *testing.T) {
		t.Parallel()

		payload := serializers.EncodeED(privateKey)
		payload.D = base64.RawURLEncoding.EncodeToString(privateKey)

		decodedPrivateKey, _, err := serializers.DecodeED(payload)
		require.NoError(t, err)
		require.True(t, privateKey.Equal(decodedPrivateKey))
	})

	t.Run("Error/MismatchedPublicKey", func(t *testing.T) {
		t.Parallel()

		payload := rfc8037Key
		payload.X = serializers.EncodeED(publicKey).X

		_, _, err := serializers.DecodeED(&payload)
		require.ErrorIs(t, err, serializers.ErrInvalidEDKey)
	})

	t.Run("Error/PrivateKeySize", func(t *testing.T) {
		t.Parallel()

		payload := rfc8037Key
		payload.D = base64.RawURLEncoding.EncodeToString(make([]byte, 31))

		_, _, err := serializers.DecodeED(&payload)
		require.ErrorIs(t, err, serializers.ErrInvalidEDKey)
	})
}
