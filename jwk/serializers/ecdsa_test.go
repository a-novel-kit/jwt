package serializers_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt/jwk/serializers"
)

func TestEC(t *testing.T) {
	t.Parallel()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	publicKey := &privateKey.PublicKey

	t.Run("PrivateKey", func(t *testing.T) {
		t.Parallel()

		payload, err := serializers.EncodeEC(privateKey)
		require.NoError(t, err)

		decodedPrivateKey, decodedPublicKey, err := serializers.DecodeEC(payload)
		require.NoError(t, err)

		require.True(t, privateKey.Equal(decodedPrivateKey))
		require.True(t, publicKey.Equal(decodedPublicKey))
	})

	t.Run("PublicKey", func(t *testing.T) {
		t.Parallel()

		payload, err := serializers.EncodeEC(publicKey)
		require.NoError(t, err)

		decodedPrivateKey, decodedPublicKey, err := serializers.DecodeEC(payload)
		require.NoError(t, err)

		require.Nil(t, decodedPrivateKey)
		require.True(t, publicKey.Equal(decodedPublicKey))
	})
}
