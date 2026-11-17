package jwt_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt/v2"
	"github.com/a-novel-kit/jwt/v2/jwa"
)

func TestNewBasicClaims(t *testing.T) {
	t.Parallel()

	t.Run("Success", func(t *testing.T) {
		t.Parallel()

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

	t.Run("Success/Expiration", func(t *testing.T) {
		t.Parallel()

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

	t.Run("Success/Target", func(t *testing.T) {
		t.Parallel()

		claims, err := jwt.NewBasicClaims(nil, jwt.ClaimsProducerConfig{
			TargetConfig: jwt.TargetConfig{
				Issuer:   "issuer",
				Subject:  "subject",
				Audience: jwa.Audience{"audience"},
			},
		})
		require.NoError(t, err)

		require.NotEmpty(t, claims.Jti)
		require.WithinDuration(t, time.Now(), time.Unix(claims.Iat, 0), time.Second)
		require.WithinDuration(t, time.Now(), time.Unix(claims.Nbf, 0), time.Second)

		require.Equal(t, "issuer", claims.Iss)
		require.Equal(t, "subject", claims.Sub)
		require.Equal(t, jwa.Audience{"audience"}, claims.Aud)

		require.Empty(t, claims.Exp)
	})

	t.Run("Success/CustomFields", func(t *testing.T) {
		t.Parallel()

		customClaims := map[string]any{"foo": "bar"}
		claims, err := jwt.NewBasicClaims(customClaims, jwt.ClaimsProducerConfig{})
		require.NoError(t, err)

		var decodedCustom map[string]any

		require.NoError(t, json.Unmarshal(claims.Payload, &decodedCustom))

		require.Equal(t, customClaims, decodedCustom)
	})

	// The success half of Error/ReservedCustomFields: an unreserved custom member joins the encoding
	// beside the registered claims NewBasicClaims sets.
	t.Run("Success/UnreservedCustomFields", func(t *testing.T) {
		t.Parallel()

		claims, err := jwt.NewBasicClaims(
			map[string]any{"role": "admin"},
			jwt.ClaimsProducerConfig{TTL: time.Hour},
		)
		require.NoError(t, err)

		encoded, err := json.Marshal(claims)
		require.NoError(t, err)

		var payload map[string]any

		require.NoError(t, json.Unmarshal(encoded, &payload))
		require.Equal(t, "admin", payload["role"])
		require.NotZero(t, payload["exp"], "the producer's own exp must survive")
	})

	t.Run("Error/ReservedCustomFields", func(t *testing.T) {
		t.Parallel()

		registeredClaims := []string{"exp", "sub", "iss", "aud", "jti", "nbf", "iat"}

		for _, name := range registeredClaims {
			t.Run(name, func(t *testing.T) {
				t.Parallel()

				claims, err := jwt.NewBasicClaims(
					map[string]any{name: "injected"},
					jwt.ClaimsProducerConfig{TTL: time.Hour},
				)
				require.NoError(t, err)

				// NewBasicClaims only stores the payload; the merge happens when the
				// claims are encoded, which is where every earlier check has already
				// finished.
				_, err = json.Marshal(claims)
				require.ErrorIs(t, err, jwa.ErrReservedMember)
				require.ErrorContains(t, err, name)
			})
		}
	})
}
