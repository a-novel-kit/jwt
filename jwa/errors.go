package jwa

import (
	"errors"

	"github.com/a-novel-kit/jwt/v2/jwa/internal"
)

// ErrUnsupportedKeyType is returned when an operation receives a key whose
// type it does not support.
var ErrUnsupportedKeyType = errors.New("unsupported key type")

// ErrReservedMember is returned by JWH, Claims and JWK marshaling when the
// custom payload names a registered parameter. It is re-exported here because
// the check itself lives in an internal package a consumer cannot import.
var ErrReservedMember = internal.ErrReservedMember
