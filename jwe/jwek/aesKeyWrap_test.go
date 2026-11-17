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
