package serializers_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt/jwk/serializers"
)

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
}
