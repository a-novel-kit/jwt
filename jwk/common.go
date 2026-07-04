// Package jwk generates and consumes JSON Web Keys for the jwt toolkit.
//
// Each supported algorithm family exposes a matching pair of helpers: a Generate function that
// mints fresh key material and returns it as a typed [Key], and a Consume function that parses an
// external JSON Web Key back into that typed key. A [Source] wraps a fetcher and caches parsed
// keys so a caller can look them up by ID when verifying tokens.
package jwk

import (
	"errors"

	"github.com/a-novel-kit/jwt/v2/jwa"
)

// ErrJWKMismatch is returned when a JSON Web Key does not match the preset it is parsed against —
// a different algorithm, key type, use, or set of key operations.
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
