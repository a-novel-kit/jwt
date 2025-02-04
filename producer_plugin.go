package jwt

import (
	"context"
	"errors"

	"github.com/a-novel-kit/jwt/jwa"
)

var (
	ErrConflictingHeader = errors.New("conflicting header")
	ErrInvalidSecretKey  = errors.New("invalid secret key")
)

// ProducerPlugin is an operation performed on a token to transform it.
//
// Each JWT operation MUST do 2 things:
//   - Describe itself in the header
//   - Perform a transformation on the final token
//
// While this interface is generic, some operations might be exclusive, or require a certain order. If that happens,
// an operation may fail with the ErrUnsupportedTokenFormat error.
type ProducerPlugin interface {
	Header(ctx context.Context, header *jwa.JWH) (modifiedHeader *jwa.JWH, err error)
	Transform(ctx context.Context, header *jwa.JWH, token string) (modifiedToken string, err error)
}

// ProducerStaticPlugin is much like an ProducerPlugin that does not perform any transformation on the token.
//
// Such operations usually produce intermediate values that can be used as an input to a regular operation, such
// as key derivation.
type ProducerStaticPlugin interface {
	Header(ctx context.Context, header *jwa.JWH) (modifiedHeader *jwa.JWH, err error)
}
