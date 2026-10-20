package serializers_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt/v2/jwk/serializers"
)

func TestRSA(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name   string
		primes int
	}{
		{name: "TwoPrimes", primes: 2},
		{name: "ThreePrimes", primes: 3},
		{name: "FourPrimes", primes: 4},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			privateKey, err := rsa.GenerateMultiPrimeKey(rand.Reader, testCase.primes, 2048) //nolint:staticcheck
			require.NoError(t, err)

			publicKey := &privateKey.PublicKey

			t.Run("PrivateKey", func(t *testing.T) {
				t.Parallel()

				payload := serializers.EncodeRSA(privateKey)

				// RFC 7518 §6.3.2.7 gives each prime after the second its own "oth" entry: the factor, its CRT
				// exponent, and the inverse of the product of the factors before it.
				require.Len(t, payload.Oth, testCase.primes-2)

				product := new(big.Int).Mul(privateKey.Primes[0], privateKey.Primes[1])

				for i, prime := range privateKey.Primes[2:] {
					exponent := new(big.Int).Mod(privateKey.D, new(big.Int).Sub(prime, big.NewInt(1)))
					coefficient := new(big.Int).ModInverse(product, prime)

					require.Equal(t, serializers.RSAOtherPrime{
						R: base64.RawURLEncoding.EncodeToString(prime.Bytes()),
						D: base64.RawURLEncoding.EncodeToString(exponent.Bytes()),
						T: base64.RawURLEncoding.EncodeToString(coefficient.Bytes()),
					}, payload.Oth[i])

					product.Mul(product, prime)
				}

				decodedPrivateKey, decodedPublicKey, err := serializers.DecodeRSA(payload)
				require.NoError(t, err)

				require.NoError(t, decodedPrivateKey.Validate())
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
		})
	}
}
