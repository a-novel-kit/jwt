package jws

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/a-novel-kit/jwt/v2"
	"github.com/a-novel-kit/jwt/v2/jwa"
)

// An InsecureVerifier decodes a token's payload without checking its signature. It accepts any
// well-formed token as a [jwt.RecipientPlugin], regardless of who signed it. Use it only when the
// token's authenticity is already guaranteed by other means — never for tokens from an untrusted
// source.
type InsecureVerifier struct{}

// NewInsecureVerifier returns an [InsecureVerifier], a [jwt.RecipientPlugin] that extracts a token's
// payload without any cryptographic verification. See [InsecureVerifier] for when this is safe.
func NewInsecureVerifier() *InsecureVerifier {
	return &InsecureVerifier{}
}

func (verifier *InsecureVerifier) Transform(_ context.Context, header *jwa.JWH, rawToken string) ([]byte, error) {
	token, err := jwt.DecodeToken(rawToken, &jwt.SignedTokenDecoder{})
	if err != nil {
		return nil, fmt.Errorf("(InsecureVerifier.Transform) split token: %w", err)
	}

	unsignedToken := jwt.RawToken{Header: token.Header, Payload: token.Payload}

	decoded, err := base64.RawURLEncoding.DecodeString(unsignedToken.Payload)
	if err != nil {
		return nil, fmt.Errorf("(InsecureVerifier.Transform) decode payload: %w", err)
	}

	return decoded, nil
}
