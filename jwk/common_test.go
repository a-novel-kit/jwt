package jwk_test

import (
	"testing"

	"github.com/a-novel-kit/jwt/v2/jwa"
	"github.com/a-novel-kit/jwt/v2/jwk"
)

// newPlaceholderKey returns a key whose metadata matches no preset, so every Consume function
// rejects it with jwk.ErrJWKMismatch. Source tests use it as an opaque key identified by kid alone.
func newPlaceholderKey[K any](t *testing.T, kid string) *jwk.Key[K] {
	t.Helper()

	return &jwk.Key[K]{
		JWK: &jwa.JWK{
			JWKCommon: jwa.JWKCommon{
				KTY:    "01",
				Use:    "10",
				KeyOps: jwa.KeyOps{"11"},
				Alg:    "00",
				KID:    kid,
			},
			Payload: []byte(`{"placeholder":true}`),
		},
	}
}
