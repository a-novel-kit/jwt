package jwa

import "errors"

// ErrUnsupportedKeyType is returned when an operation receives a key whose
// type it does not support.
var ErrUnsupportedKeyType = errors.New("unsupported key type")
