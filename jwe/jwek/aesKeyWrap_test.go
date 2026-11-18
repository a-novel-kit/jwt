package jwek_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt/v2"
	"github.com/a-novel-kit/jwt/v2/jwa"
	"github.com/a-novel-kit/jwt/v2/jwe/jwek"
)

func TestAESKWManager(t *testing.T) {
	t.Parallel()

	// https://datatracker.ietf.org/doc/html/rfc7516#appendix-A.3
	t.Run("Success/RFC7516A3", func(t *testing.T) {
		t.Parallel()

		manager := jwek.NewAESKWManager(
			&jwek.AESKWManagerConfig{WrapKey: mustDecodeBase64(t, "GawgguFyGrWKav7AX4VKUg")}, jwek.A128KW,
		)

		// The content encryption key of A.3.2.
		cek := []byte{
			4, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250, 63, 170, 106, 206,
			107, 124, 212, 45, 111, 107, 9, 219, 200, 177, 0, 240, 143, 156, 44, 207,
		}

		encryptedKey, err := manager.EncryptCEK(t.Context(), &jwa.JWH{}, cek)
		require.NoError(t, err)
		require.Equal(t, mustDecodeBase64(t, "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ"), encryptedKey)
	})

	t.Run("Error/UnknownEnc", func(t *testing.T) {
		t.Parallel()

		// The CEK's size comes from "enc", so a manager cannot draw one for an algorithm it does not know.
		manager := jwek.NewAESKWManager(&jwek.AESKWManagerConfig{WrapKey: randomKey(32)}, jwek.A256KW)

		_, err := manager.ComputeCEK(t.Context(), &jwa.JWH{JWHCommon: jwa.JWHCommon{Enc: "C20P"}})
		require.ErrorIs(t, err, jwt.ErrInvalidSecretKey)
		// The producer's own configuration failed, so no token was rejected.
		require.NotErrorIs(t, err, jwt.ErrTokenRejected)
	})
}
