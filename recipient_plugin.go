package jwt

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/a-novel-kit/jwt/jwa"
)

var ErrMismatchRecipientPlugin = errors.New("mismatch recipient plugin")

type RecipientPlugin interface {
	Transform(ctx context.Context, header *jwa.JWH, token string) (payload []byte, err error)
}

type DefaultRecipientPlugin struct{}

func NewDefaultRecipientPlugin() *DefaultRecipientPlugin {
	return &DefaultRecipientPlugin{}
}

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
