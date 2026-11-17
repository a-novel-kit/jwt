package jwek_test

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt/v2"
	"github.com/a-novel-kit/jwt/v2/jwa"
	"github.com/a-novel-kit/jwt/v2/jwe/jwek"
)

func TestRSAOAEPKeyEncManager(t *testing.T) {
	t.Parallel()

	t.Run("Error/ShortKey", func(t *testing.T) {
		t.Parallel()

		// RFC 7518 §4.3: RSA-OAEP needs a key of 2048 bits or more, at both ends.
		shortKey, err := rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec // The weak key is under test.
		require.NoError(t, err)

		manager := jwek.NewRSAOAEPKeyEncManager(
			&jwek.RSAOAEPKeyEncManagerConfig{EncKey: &shortKey.PublicKey}, jwek.RSAOAEP256,
		)

		header := &jwa.JWH{JWHCommon: jwa.JWHCommon{Alg: jwa.RSAOAEP256, Enc: jwa.A256GCM}}

		_, err = manager.EncryptCEK(t.Context(), header, make([]byte, 32))
		require.ErrorIs(t, err, jwt.ErrInvalidSecretKey)
	})
}

func TestRSAOAEPKeyEncDecoder(t *testing.T) {
	t.Parallel()

	t.Run("Error/ShortKey", func(t *testing.T) {
		t.Parallel()

		// RFC 7518 §4.3: RSA-OAEP needs a key of 2048 bits or more, at both ends.
		shortKey, err := rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec // The weak key is under test.
		require.NoError(t, err)

		decoder := jwek.NewRSAOAEPKeyEncDecoder(&jwek.RSAOAEPKeyEncDecoderConfig{EncKey: shortKey}, jwek.RSAOAEP256)

		header := &jwa.JWH{JWHCommon: jwa.JWHCommon{Alg: jwa.RSAOAEP256, Enc: jwa.A256GCM}}

		_, err = decoder.ComputeCEK(t.Context(), header, []byte("encrypted"))
		require.ErrorIs(t, err, jwt.ErrInvalidSecretKey)
	})
}
