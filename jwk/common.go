package jwk

import (
	"errors"

	"github.com/a-novel-kit/jwt/v2/jwa"
)

// ErrJWKMismatch is returned when a JSON Web Key does not match the preset it is parsed against, such
// as a key bound to another algorithm.
var ErrJWKMismatch = errors.New("jwk and key mismatch")

// A Key pairs a JSON Web Key with its decoded native representation of type K, such as an
// *rsa.PrivateKey or a raw byte slice. The embedded [jwa.JWK] carries the serialized form.
type Key[K any] struct {
	*jwa.JWK

	parsed K
}

// Key returns the decoded native key.
func (key *Key[K]) Key() K {
	return key.parsed
}

// NewKey pairs an already-decoded key with its JSON Web Key form.
func NewKey[K any](jwk *jwa.JWK, parsed K) *Key[K] {
	return &Key[K]{jwk, parsed}
}
