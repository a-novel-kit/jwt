package jwt

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/a-novel-kit/jwt/v2/jwa"
)

// ErrMismatchRecipientPlugin is returned by a plugin that does not recognize a token, signaling
// the Recipient to try the next plugin.
var ErrMismatchRecipientPlugin = errors.New("mismatch recipient plugin")

// A RecipientPlugin validates a token and extracts its raw claims payload. It returns
// [ErrMismatchRecipientPlugin] when the token does not match the algorithm or shape it handles, so
// the Recipient can fall through to another plugin.
type RecipientPlugin interface {
	Transform(ctx context.Context, header *jwa.JWH, token string) (payload []byte, err error)
}

// DefaultRecipientPlugin consumes unsecured tokens, those whose header carries the "none" algorithm.
// It runs no cryptographic check and returns the payload as it is, so a [Recipient] uses it only when
// its configuration lists it (RFC 7518 §3.6).
type DefaultRecipientPlugin struct{}

var _ RecipientPlugin = (*DefaultRecipientPlugin)(nil)

// NewDefaultRecipientPlugin returns a DefaultRecipientPlugin.
func NewDefaultRecipientPlugin() *DefaultRecipientPlugin {
	return &DefaultRecipientPlugin{}
}

// Transform returns the token's raw payload. It rejects any token whose algorithm is not "none" with
// [ErrMismatchRecipientPlugin].
//
// An unsecured token ends with its empty signature segment, as "header.payload." (RFC 7519 §6.1).
// Releases up to v2.6.0 issued "header.payload" instead, which is still accepted so those tokens keep
// decoding. Any non-empty signature is rejected (RFC 7518 §3.6).
func (plugin *DefaultRecipientPlugin) Transform(_ context.Context, header *jwa.JWH, rawToken string) ([]byte, error) {
	if header.Alg != jwa.None {
		return nil, fmt.Errorf(
			"(DefaultRecipientPlugin.Transform) %w: invalid algorithm %s, expected %s",
			ErrMismatchRecipientPlugin, header.Alg, jwa.None,
		)
	}

	token, err := (&RawTokenDecoder{}).Decode(strings.TrimSuffix(rawToken, "."))
	if err != nil {
		return nil, fmt.Errorf("(DefaultRecipientPlugin.Transform) decode token: %w", err)
	}

	decodedPayload, err := base64.RawURLEncoding.DecodeString(token.Payload)
	if err != nil {
		return nil, fmt.Errorf("(DefaultRecipientPlugin.Transform) %w: decode payload: %w", ErrUnsupportedTokenFormat, err)
	}

	return decodedPayload, nil
}
