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

// A ProducerPlugin transforms a token during issuance. Header records the plugin's operation in the
// header, and Transform then applies it to the serialized token, by signing or encrypting it for
// example. Plugins run in the order they are configured. A plugin rejects a token it cannot apply,
// such as with [ErrConflictingHeader] when an earlier plugin already set a header field it needs.
type ProducerPlugin interface {
	Header(ctx context.Context, header *jwa.JWH) (modifiedHeader *jwa.JWH, err error)
	Transform(ctx context.Context, header *jwa.JWH, token string) (modifiedToken string, err error)
}

// A ProducerStaticPlugin only amends the header and leaves the serialized token alone. It sets
// values a transforming plugin reads later, such as the key ID a sourced signer signs with.
type ProducerStaticPlugin interface {
	Header(ctx context.Context, header *jwa.JWH) (modifiedHeader *jwa.JWH, err error)
}
