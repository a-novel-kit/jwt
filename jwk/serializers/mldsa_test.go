package serializers_test

import (
	"crypto/mldsa"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt/v2/jwk/serializers"
)

func TestMLDSA(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string

		params mldsa.Parameters
	}{
		{name: "MLDSA44", params: mldsa.MLDSA44()},
		{name: "MLDSA65", params: mldsa.MLDSA65()},
		{name: "MLDSA87", params: mldsa.MLDSA87()},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			privateKey, err := mldsa.GenerateKey(testCase.params)
			require.NoError(t, err)

			publicKey := privateKey.PublicKey()

			t.Run("PrivateKey", func(t *testing.T) {
				t.Parallel()

				payload := serializers.EncodeMLDSA(privateKey)

				seed, err := base64.RawURLEncoding.DecodeString(payload.Priv)
				require.NoError(t, err)
				require.Len(t, seed, mldsa.PrivateKeySize, "RFC 9964 §4 serializes the seed")

				decodedPrivateKey, decodedPublicKey, err := serializers.DecodeMLDSA(payload, testCase.params)
				require.NoError(t, err)

				require.True(t, privateKey.Equal(decodedPrivateKey))
				require.True(t, publicKey.Equal(decodedPublicKey))
			})

			t.Run("PublicKey", func(t *testing.T) {
				t.Parallel()

				payload := serializers.EncodeMLDSA(publicKey)
				require.Empty(t, payload.Priv)

				decodedPrivateKey, decodedPublicKey, err := serializers.DecodeMLDSA(payload, testCase.params)
				require.NoError(t, err)

				require.Nil(t, decodedPrivateKey)
				require.True(t, publicKey.Equal(decodedPublicKey))
			})
		})
	}

	privateKey, err := mldsa.GenerateKey(mldsa.MLDSA44())
	require.NoError(t, err)

	t.Run("Error/WrongParameterSet", func(t *testing.T) {
		t.Parallel()

		_, _, err := serializers.DecodeMLDSA(serializers.EncodeMLDSA(privateKey), mldsa.MLDSA65())
		require.ErrorIs(t, err, serializers.ErrInvalidMLDSAKey)
	})

	t.Run("Error/SeedSize", func(t *testing.T) {
		t.Parallel()

		payload := serializers.EncodeMLDSA(privateKey)
		payload.Priv = base64.RawURLEncoding.EncodeToString(make([]byte, mldsa.PrivateKeySize+1))

		_, _, err := serializers.DecodeMLDSA(payload, mldsa.MLDSA44())
		require.ErrorIs(t, err, serializers.ErrInvalidMLDSAKey)
	})

	t.Run("Error/MismatchedPublicKey", func(t *testing.T) {
		t.Parallel()

		otherKey, err := mldsa.GenerateKey(mldsa.MLDSA44())
		require.NoError(t, err)

		payload := serializers.EncodeMLDSA(privateKey)
		payload.Pub = serializers.EncodeMLDSA(otherKey.PublicKey()).Pub

		_, _, err = serializers.DecodeMLDSA(payload, mldsa.MLDSA44())
		require.ErrorIs(t, err, serializers.ErrInvalidMLDSAKey)
	})
}
