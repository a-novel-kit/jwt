package jwa

import "github.com/a-novel-kit/jwt/v2/jwa/internal"

// ErrReservedMember is returned by JWH, Claims and JWK marshaling when the
// custom payload names a registered parameter, and by their unmarshaling when
// the object holds a case variant of one, such as "ALG". It is re-exported here
// because the check itself lives in an internal package a consumer cannot import.
var ErrReservedMember = internal.ErrReservedMember
