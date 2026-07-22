// Package testutils provides helpers for exercising the jwt packages in tests,
// standing in for the live key infrastructure of a real deployment.
package testutils

import (
	"context"
	"testing"

	"github.com/a-novel-kit/jwt/v2/jwa"
	"github.com/a-novel-kit/jwt/v2/jwk"
)

// NewStaticKeysSource returns a [jwk.Source] backed by a fixed, in-memory set of keys, so a test can
// serve known keys without a live JWKS endpoint. Keys are served in the order given. The input stays
// typed for caller convenience, but the Source is raw — the consuming signer or verifier decodes it.
func NewStaticKeysSource[T any](t *testing.T, keys []*jwk.Key[T]) *jwk.Source {
	t.Helper()

	return jwk.NewSource(jwk.SourceConfig{
		Fetch: func(_ context.Context) ([]*jwa.JWK, error) {
			mapped := make([]*jwa.JWK, len(keys))
			for i, key := range keys {
				mapped[i] = key.JWK
			}

			return mapped, nil
		},
	})
}
