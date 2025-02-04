package jwk

import (
	"errors"

	"github.com/a-novel-kit/jwt/jwa"
)

var ErrJWKMismatch = errors.New("jwk and key mismatch")

type Key[K any] struct {
	*jwa.JWK
	parsed K
}

func (key *Key[K]) Key() K {
	return key.parsed
}

func NewKey[K any](jwk *jwa.JWK, parsed K) *Key[K] {
	return &Key[K]{jwk, parsed}
}
