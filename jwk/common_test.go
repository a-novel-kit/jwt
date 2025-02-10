package jwk_test

import (
	"testing"

	"github.com/a-novel-kit/jwt/jwa"
	"github.com/a-novel-kit/jwt/jwk"
)

func newBullshitKey[K any](t *testing.T, kid string) *jwk.Key[K] {
	t.Helper()

	return &jwk.Key[K]{
		JWK: &jwa.JWK{
			JWKCommon: jwa.JWKCommon{
				KTY:    "01",
				Use:    "10",
				KeyOps: []jwa.KeyOp{"11"},
				Alg:    "00",
				KID:    kid,
			},
			Payload: []byte(`{"your":"mom"}`),
		},
	}
}
