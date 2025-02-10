package serializers_test

import (
	"crypto/ecdh"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt/jwk/serializers"
)

func TestECDH(t *testing.T) {
	t.Parallel()

	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)

	publicKey := privateKey.PublicKey()

	t.Run("PrivateKey", func(t *testing.T) {
		t.Parallel()

		payload, err := serializers.EncodeECDH(privateKey)
		require.NoError(t, err)

		decodedPrivateKey, decodedPublicKey, err := serializers.DecodeECDH(payload)
		require.NoError(t, err)

		require.True(t, privateKey.Equal(decodedPrivateKey))
		require.True(t, publicKey.Equal(decodedPublicKey))
	})

	t.Run("PublicKey", func(t *testing.T) {
		t.Parallel()

		payload, err := serializers.EncodeECDH(publicKey)
		require.NoError(t, err)

		decodedPrivateKey, decodedPublicKey, err := serializers.DecodeECDH(payload)
		require.NoError(t, err)

		require.Nil(t, decodedPrivateKey)
		require.True(t, publicKey.Equal(decodedPublicKey))
	})
}
