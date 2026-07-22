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
// coordinate size.
//
// The fixture is a P-256 key whose x coordinate falls below 2^248, so its minimal encoding is 31
// bytes, one short of the fixed 32. Roughly one coordinate in 256 is like this, so a randomly
// generated key almost never exercises it. DecodeEC reads through big.Int.SetBytes, which accepts
// any length, so only a consumer in another runtime rejects the short value.
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

	// Guard the fixture: once this stops holding, the test below tests nothing and must be re-seeded
	// with another short-coordinate key. The check reads the uncompressed point (0x04 || X || Y,
	// fixed width), whose leading zero byte is what makes big.Int's minimal encoding come out short.
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
