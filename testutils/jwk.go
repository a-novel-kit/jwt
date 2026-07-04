// Package testutils provides helpers for exercising the jwt packages in tests,
// standing in for the live key infrastructure a real deployment would rely on.
package testutils

import (
	"context"
	"errors"
	"testing"

	"github.com/a-novel-kit/jwt/jwa"
	"github.com/a-novel-kit/jwt/jwk"
)

// NewStaticKeysSource returns a [jwk.Source] backed by a fixed, in-memory set of keys, so a test can
// serve known keys without a live JWKS endpoint. Keys are served in the order given, and a lookup
// matches on KID.
func NewStaticKeysSource[T any](t *testing.T, keys []*jwk.Key[T]) *jwk.Source[T] {
	t.Helper()

	return jwk.NewGenericSource[T](jwk.SourceConfig{
		Fetch: func(_ context.Context) ([]*jwa.JWK, error) {
			mapped := make([]*jwa.JWK, len(keys))
			for i, key := range keys {
				mapped[i] = key.JWK
			}

			return mapped, nil
		},
	}, func(_ context.Context, jwk *jwa.JWK) (*jwk.Key[T], error) {
		for _, key := range keys {
			if key.KID == jwk.KID {
				return key, nil
			}
		}

		return nil, errors.New("key not found")
	})
}
