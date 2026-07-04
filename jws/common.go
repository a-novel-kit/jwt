package jws

import "errors"

// ErrInvalidSignature is returned by a verifier when a token's signature does not match its header
// and payload, or when the signature is malformed. A source-backed verifier also returns it once no
// candidate key accepts the token.
var ErrInvalidSignature = errors.New("invalid signature")

// minRSAKeyBits is the smallest RSA modulus the RS* and PS* algorithms accept, per RFC 7518 §3.3
// and §3.5 ("A key of size 2048 bits or larger MUST be used"). Enforced at both sign and verify.
const minRSAKeyBits = 2048
