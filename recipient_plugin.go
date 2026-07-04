package jwt

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/a-novel-kit/jwt/jwa"
)

// ErrMismatchRecipientPlugin is returned by a plugin that does not recognize a token, signaling
// the Recipient to try the next plugin instead of failing.
var ErrMismatchRecipientPlugin = errors.New("mismatch recipient plugin")

// A RecipientPlugin validates a token and extracts its raw claims payload. It returns
// [ErrMismatchRecipientPlugin] when the token does not match the algorithm or shape it handles, so
// the Recipient can fall through to another plugin.
type RecipientPlugin interface {
	Transform(ctx context.Context, header *jwa.JWH, token string) (payload []byte, err error)
}

// DefaultRecipientPlugin consumes unsecured tokens: those whose header carries no algorithm or the
// "none" algorithm. It runs no cryptographic check and returns the payload as it is.
type DefaultRecipientPlugin struct{}

// NewDefaultRecipientPlugin returns a DefaultRecipientPlugin.
func NewDefaultRecipientPlugin() *DefaultRecipientPlugin {
	return &DefaultRecipientPlugin{}
}

// Transform returns the token's raw payload. It rejects any token that names a real signing or
// encryption algorithm with [ErrMismatchRecipientPlugin].
func (plugin *DefaultRecipientPlugin) Transform(_ context.Context, header *jwa.JWH, rawToken string) ([]byte, error) {
	if header.Alg != "" && header.Alg != jwa.None {
		return nil, fmt.Errorf(
			"(DefaultRecipientPlugin.Transform) %w: invalid algorithm %s, expected %s",
			ErrMismatchRecipientPlugin, header.Alg, jwa.None,
		)
	}

	token, err := DecodeToken(rawToken, &RawTokenDecoder{})
	if err != nil {
		return nil, fmt.Errorf("(DefaultRecipientPlugin.Transform) decode token: %w", err)
	}

	decodedPayload, err := base64.RawURLEncoding.DecodeString(token.Payload)
	if err != nil {
		return nil, fmt.Errorf("(DefaultRecipientPlugin.Transform) decode payload: %w", err)
	}

	return decodedPayload, nil
}
