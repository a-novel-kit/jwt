package jwe

import "errors"

// ErrInvalidSecret is returned when the content encryption key resolved for a token
// has the wrong length for the chosen algorithm, or when an authentication tag fails
// to verify during decryption.
var ErrInvalidSecret = errors.New("invalid secret")
