package jws

import "errors"

// ErrInvalidSignature is returned by a verifier when a token's signature does not match its header
// and payload, or when the signature is malformed. A source-backed verifier also returns it once no
// candidate key accepts the token.
var ErrInvalidSignature = errors.New("invalid signature")
