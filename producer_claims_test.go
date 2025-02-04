package jwt_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt"
)

func TestNewBasicClaims(t *testing.T) {
	t.Run("DefaultsOnly", func(t *testing.T) {
		claims, err := jwt.NewBasicClaims(nil, jwt.ClaimsProducerConfig{})
		require.NoError(t, err)

		require.NotEmpty(t, claims.Jti)
		require.WithinDuration(t, time.Now(), time.Unix(claims.Iat, 0), time.Second)
		require.WithinDuration(t, time.Now(), time.Unix(claims.Nbf, 0), time.Second)

		require.Empty(t, claims.Iss)
		require.Empty(t, claims.Sub)
		require.Empty(t, claims.Aud)
		require.Empty(t, claims.Exp)
	})

	t.Run("WithExpiration", func(t *testing.T) {
		claims, err := jwt.NewBasicClaims(nil, jwt.ClaimsProducerConfig{
			TTL: time.Minute,
		})
		require.NoError(t, err)

		require.NotEmpty(t, claims.Jti)
		require.WithinDuration(t, time.Now(), time.Unix(claims.Iat, 0), time.Second)
		require.WithinDuration(t, time.Now(), time.Unix(claims.Nbf, 0), time.Second)
		require.WithinDuration(t, time.Now().Add(time.Minute), time.Unix(claims.Exp, 0), time.Second)

		require.Empty(t, claims.Iss)
		require.Empty(t, claims.Sub)
		require.Empty(t, claims.Aud)
	})

	t.Run("WithTarget", func(t *testing.T) {
		claims, err := jwt.NewBasicClaims(nil, jwt.ClaimsProducerConfig{
			TargetConfig: jwt.TargetConfig{
				Issuer:   "issuer",
				Subject:  "subject",
				Audience: "audience",
			},
		})
		require.NoError(t, err)

		require.NotEmpty(t, claims.Jti)
		require.WithinDuration(t, time.Now(), time.Unix(claims.Iat, 0), time.Second)
		require.WithinDuration(t, time.Now(), time.Unix(claims.Nbf, 0), time.Second)

		require.Equal(t, "issuer", claims.Iss)
		require.Equal(t, "subject", claims.Sub)
		require.Equal(t, "audience", claims.Aud)

		require.Empty(t, claims.Exp)
	})

	t.Run("WithCustomFields", func(t *testing.T) {
		customClaims := map[string]any{"foo": "bar"}
		claims, err := jwt.NewBasicClaims(customClaims, jwt.ClaimsProducerConfig{})
		require.NoError(t, err)

		var decodedCustom map[string]any
		require.NoError(t, json.Unmarshal(claims.Payload, &decodedCustom))

		require.Equal(t, customClaims, decodedCustom)
	})
}
