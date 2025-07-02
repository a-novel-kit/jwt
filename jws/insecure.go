package jws

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/a-novel-kit/jwt"
	"github.com/a-novel-kit/jwt/jwa"
)

type InsecureVerifier struct{}

func (verifier *InsecureVerifier) Transform(_ context.Context, header *jwa.JWH, rawToken string) ([]byte, error) {
	token, err := jwt.DecodeToken(rawToken, &jwt.SignedTokenDecoder{})
	if err != nil {
		return nil, fmt.Errorf("(RSAVerifier.Transform) split token: %w", err)
	}

	unsignedToken := jwt.RawToken{Header: token.Header, Payload: token.Payload}

	decoded, err := base64.RawURLEncoding.DecodeString(unsignedToken.Payload)
	if err != nil {
		return nil, fmt.Errorf("(RSAVerifier.Transform) decode payload: %w", err)
	}

	return decoded, nil
}

func NewInsecureVerifier() *InsecureVerifier {
	return &InsecureVerifier{}
}
