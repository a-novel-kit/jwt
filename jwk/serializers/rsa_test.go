package serializers_test

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt/jwk/serializers"
)

func TestRSA(t *testing.T) {
	t.Parallel()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	publicKey := &privateKey.PublicKey

	t.Run("PrivateKey", func(t *testing.T) {
		t.Parallel()

		payload := serializers.EncodeRSA(privateKey)

		decodedPrivateKey, decodedPublicKey, err := serializers.DecodeRSA(payload)
		require.NoError(t, err)

		require.True(t, privateKey.Equal(decodedPrivateKey))
		require.True(t, publicKey.Equal(decodedPublicKey))
	})

	t.Run("PublicKey", func(t *testing.T) {
		t.Parallel()

		payload := serializers.EncodeRSA(publicKey)

		decodedPrivateKey, decodedPublicKey, err := serializers.DecodeRSA(payload)
		require.NoError(t, err)

		require.Nil(t, decodedPrivateKey)
		require.True(t, publicKey.Equal(decodedPublicKey))
	})
}
