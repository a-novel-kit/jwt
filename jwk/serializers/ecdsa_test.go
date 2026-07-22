package serializers_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt/v2/jwk/serializers"
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

// TestECCoordinateWidth pins the RFC 7518 requirement that x and y are encoded at the curve's full
// coordinate size rather than big.Int's minimal encoding.
//
// The fixture is a P-256 key whose x coordinate happens to be below 2^248, so its minimal encoding
// is 31 bytes instead of 32. Roughly one coordinate in 256 is like this, which is why a randomly
// generated key — as the round-trip tests above use — almost never exercises the case, and why the
// round trip could not catch it anyway: DecodeEC reads through big.Int.SetBytes, which accepts any
// length. Only a consumer in another runtime rejects the short value.
func TestECCoordinateWidth(t *testing.T) {
	t.Parallel()

	const (
		p256ByteLen  = 32
		shortXKeyHex = "d0b0ae4750701a80ac4b024ce8d70fa3eec161900a1e8b636a88190a5f3102e9"
	)

	rawKey, err := hex.DecodeString(shortXKeyHex)
	require.NoError(t, err)

	privateKey, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), rawKey)
	require.NoError(t, err)

	// Guard the fixture itself: if this ever stops holding, the test below silently stops testing
	// anything and must be re-seeded with another short-coordinate key. Read through the
	// uncompressed point (0x04 || X || Y, fixed width) rather than the deprecated PublicKey.X — a
	// leading zero byte there is exactly what makes big.Int's minimal encoding come out short.
	rawPoint, err := privateKey.PublicKey.Bytes()
	require.NoError(t, err)
	require.Zero(t, rawPoint[1], "fixture no longer has a short x coordinate")

	for _, testCase := range []struct {
		name    string
		payload func() (*serializers.ECPayload, error)
	}{
		{
			name:    "PrivateKey",
			payload: func() (*serializers.ECPayload, error) { return serializers.EncodeEC(privateKey) },
		},
		{
			name:    "PublicKey",
			payload: func() (*serializers.ECPayload, error) { return serializers.EncodeEC(&privateKey.PublicKey) },
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			payload, err := testCase.payload()
			require.NoError(t, err)

			x, err := base64.RawURLEncoding.DecodeString(payload.X)
			require.NoError(t, err)
			require.Len(t, x, p256ByteLen, "x must be padded to the curve's coordinate size")

			y, err := base64.RawURLEncoding.DecodeString(payload.Y)
			require.NoError(t, err)
			require.Len(t, y, p256ByteLen, "y must be padded to the curve's coordinate size")
		})
	}
}
