package serializers_test

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt/v2/jwa"
	"github.com/a-novel-kit/jwt/v2/jwk/serializers"
)

// rfc7518BobKey is the P-256 private key of RFC 7518 Appendix C. It pins the "EC" layout: two
// full-size coordinates and a full-size scalar.
//
// https://datatracker.ietf.org/doc/html/rfc7518#appendix-C
var rfc7518BobKey = serializers.ECDHPayload{
	Crv: "P-256",
	X:   "weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
	Y:   "e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck",
	D:   "VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw",
}

func TestECDH(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string

		curve ecdh.Curve
		kty   jwa.KTY
	}{
		{name: "X25519", curve: ecdh.X25519(), kty: jwa.KTYOKP},
		{name: "P256", curve: ecdh.P256(), kty: jwa.KTYEC},
		{name: "P384", curve: ecdh.P384(), kty: jwa.KTYEC},
		{name: "P521", curve: ecdh.P521(), kty: jwa.KTYEC},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			privateKey, err := testCase.curve.GenerateKey(rand.Reader)
			require.NoError(t, err)

			publicKey := privateKey.PublicKey()

			require.Equal(t, testCase.kty, serializers.ECDHKeyType(testCase.curve))

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
				require.Empty(t, payload.D)

				decodedPrivateKey, decodedPublicKey, err := serializers.DecodeECDH(payload)
				require.NoError(t, err)

				require.Nil(t, decodedPrivateKey)
				require.True(t, publicKey.Equal(decodedPublicKey))
			})
		})
	}

	t.Run("Success/RFC7518Vector", func(t *testing.T) {
		t.Parallel()

		decodedPrivateKey, _, err := serializers.DecodeECDH(&rfc7518BobKey)
		require.NoError(t, err)

		payload, err := serializers.EncodeECDH(decodedPrivateKey)
		require.NoError(t, err)
		require.Equal(t, rfc7518BobKey, *payload)
	})

	t.Run("Error/MismatchedPublicKey", func(t *testing.T) {
		t.Parallel()

		otherKey, err := ecdh.P256().GenerateKey(rand.Reader)
		require.NoError(t, err)

		payload := rfc7518BobKey
		other, err := serializers.EncodeECDH(otherKey.PublicKey())
		require.NoError(t, err)

		payload.X, payload.Y = other.X, other.Y

		_, _, err = serializers.DecodeECDH(&payload)
		require.ErrorIs(t, err, serializers.ErrInvalidECDHKey)
	})

	t.Run("Error/ShortCoordinate", func(t *testing.T) {
		t.Parallel()

		// RFC 7518 §6.2.1.2: a coordinate keeps its leading zero octets, so a 31-byte x is malformed.
		x, err := base64.RawURLEncoding.DecodeString(rfc7518BobKey.X)
		require.NoError(t, err)

		payload := rfc7518BobKey
		payload.X = base64.RawURLEncoding.EncodeToString(x[1:])
		payload.D = ""

		_, _, err = serializers.DecodeECDH(&payload)
		require.ErrorIs(t, err, serializers.ErrInvalidECDHKey)
	})

	t.Run("Error/OffCurve", func(t *testing.T) {
		t.Parallel()

		payload := rfc7518BobKey
		payload.Y = payload.X
		payload.D = ""

		_, _, err := serializers.DecodeECDH(&payload)
		require.ErrorIs(t, err, serializers.ErrInvalidECDHKey)
	})

	t.Run("Error/UnsupportedCurve", func(t *testing.T) {
		t.Parallel()

		payload := rfc7518BobKey
		payload.Crv = "X448"

		_, _, err := serializers.DecodeECDH(&payload)
		require.ErrorIs(t, err, serializers.ErrUnsupportedCurve)
	})
}
