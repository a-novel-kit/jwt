package jwt

import (
	"context"
	"errors"

	"github.com/a-novel-kit/jwt/v2/jwa"
)

var (
	// ErrConflictingHeader is returned when a plugin needs a header field that an earlier plugin has
	// already set.
	ErrConflictingHeader = errors.New("conflicting header")
	// ErrInvalidSecretKey is returned when a plugin's key material does not fit its algorithm, such as
	// a key size that mismatches the chosen hash.
	ErrInvalidSecretKey = errors.New("invalid secret key")
)

// A ProducerPlugin transforms a token during issuance. Each plugin does two things: it records its
// operation in the header, then transforms the serialized token to match — signing or encrypting
// it, for example. Plugins run in the order they are configured. Because some are mutually
// exclusive or order-dependent, a plugin may reject a token it cannot apply, for instance with
// [ErrConflictingHeader] when an earlier plugin already claimed a header field it needs.
type ProducerPlugin interface {
	Header(ctx context.Context, header *jwa.JWH) (modifiedHeader *jwa.JWH, err error)
	Transform(ctx context.Context, header *jwa.JWH, token string) (modifiedToken string, err error)
}

// A ProducerStaticPlugin is a plugin that only amends the header and performs no token
// transformation. It typically derives an intermediate value — a wrapped key, say — that a later
// transforming plugin consumes.
type ProducerStaticPlugin interface {
	Header(ctx context.Context, header *jwa.JWH) (modifiedHeader *jwa.JWH, err error)
}
