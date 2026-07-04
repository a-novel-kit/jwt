package jws

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/a-novel-kit/jwt"
	"github.com/a-novel-kit/jwt/jwa"
	"github.com/a-novel-kit/jwt/jwk"
)

// An ED25519Signer signs tokens with the Ed25519 EdDSA scheme as a [jwt.ProducerPlugin]. Build one
// with [NewED25519Signer].
type ED25519Signer struct {
	secretKey ed25519.PrivateKey
}

// NewED25519Signer returns a [jwt.ProducerPlugin] that signs tokens with Ed25519 (EdDSA).
//
// See RFC 8032, section 3.3: https://datatracker.ietf.org/doc/html/rfc8032#section-3.3
func NewED25519Signer(secretKey ed25519.PrivateKey) *ED25519Signer {
	return &ED25519Signer{
		secretKey: secretKey,
	}
}

func (signer *ED25519Signer) Header(_ context.Context, header *jwa.JWH) (*jwa.JWH, error) {
	if !header.Alg.Empty() {
		return nil, fmt.Errorf("(ED25519Signer.Header) %w: alg field already set", jwt.ErrConflictingHeader)
	}

	header.Alg = jwa.EdDSA

	return header, nil
}

func (signer *ED25519Signer) Transform(_ context.Context, _ *jwa.JWH, rawToken string) (string, error) {
	token, err := jwt.DecodeToken(rawToken, &jwt.RawTokenDecoder{})
	if err != nil {
		return "", fmt.Errorf("(ED25519Signer.Transform) split token: %w", err)
	}

	signature := ed25519.Sign(signer.secretKey, token.Bytes())

	return jwt.SignedToken{
		Header:    token.Header,
		Payload:   token.Payload,
		Signature: base64.RawURLEncoding.EncodeToString(signature),
	}.String(), nil
}

// An ED25519Verifier verifies Ed25519-signed tokens as a [jwt.RecipientPlugin]. Build one with
// [NewED25519Verifier]. It returns [ErrInvalidSignature] when the signature does not match.
type ED25519Verifier struct {
	publicKey ed25519.PublicKey
}

// NewED25519Verifier returns a [jwt.RecipientPlugin] that verifies Ed25519-signed (EdDSA) tokens.
//
// See RFC 8032, section 3.3: https://datatracker.ietf.org/doc/html/rfc8032#section-3.3
func NewED25519Verifier(publicKey ed25519.PublicKey) *ED25519Verifier {
	return &ED25519Verifier{
		publicKey: publicKey,
	}
}

func (verifier *ED25519Verifier) Transform(_ context.Context, header *jwa.JWH, rawToken string) ([]byte, error) {
	if header.Alg != jwa.EdDSA {
		return nil, fmt.Errorf(
			"(ED25519Verifier.Transform) %w: invalid algorithm %s, expected %s",
			jwt.ErrMismatchRecipientPlugin, header.Alg, jwa.EdDSA,
		)
	}

	token, err := jwt.DecodeToken(rawToken, &jwt.SignedTokenDecoder{})
	if err != nil {
		return nil, fmt.Errorf("(ED25519Verifier.Transform) split source: %w", err)
	}

	unsignedToken := jwt.RawToken{Header: token.Header, Payload: token.Payload}

	sigBytes, err := base64.RawURLEncoding.DecodeString(token.Signature)
	if err != nil {
		return nil, fmt.Errorf("(ED25519Verifier.Transform) decode signature: %w", err)
	}

	if !ed25519.Verify(verifier.publicKey, unsignedToken.Bytes(), sigBytes) {
		return nil, fmt.Errorf("(ED25519Verifier.Transform) %w", ErrInvalidSignature)
	}

	decoded, err := base64.RawURLEncoding.DecodeString(token.Payload)
	if err != nil {
		return nil, fmt.Errorf("(ED25519Verifier.Transform) decode payload: %w", err)
	}

	return decoded, nil
}

// A SourcedED25519Signer signs like an [ED25519Signer] but resolves its key from a [jwk.Source] at
// each call, so the plugin follows key rotation instead of pinning one key. Build one with
// [NewSourcedED25519Signer].
type SourcedED25519Signer struct {
	source *jwk.Source[ed25519.PrivateKey]
}

// NewSourcedED25519Signer returns a [jwt.ProducerPlugin] that signs tokens with Ed25519 (EdDSA),
// drawing the key from the source for the header's KID.
//
// See RFC 8032, section 3.3: https://datatracker.ietf.org/doc/html/rfc8032#section-3.3
func NewSourcedED25519Signer(source *jwk.Source[ed25519.PrivateKey]) *SourcedED25519Signer {
	return &SourcedED25519Signer{
		source: source,
	}
}

func (signer *SourcedED25519Signer) Header(ctx context.Context, header *jwa.JWH) (*jwa.JWH, error) {
	key, err := signer.source.Get(ctx, header.KID)
	if err != nil {
		return nil, fmt.Errorf("(SourcedED25519Signer.Header) %w", err)
	}

	// Stamp the resolved key's ID into the header so recipients can select it for verification.
	if header.KID == "" {
		header.KID = key.KID
	}

	return NewED25519Signer(key.Key()).Header(ctx, header)
}

func (signer *SourcedED25519Signer) Transform(ctx context.Context, header *jwa.JWH, rawToken string) (string, error) {
	key, err := signer.source.Get(ctx, header.KID)
	if err != nil {
		return "", fmt.Errorf("(SourcedED25519Signer.Transform) %w", err)
	}

	return NewED25519Signer(key.Key()).Transform(ctx, header, rawToken)
}

// A SourcedED25519Verifier verifies like an [ED25519Verifier] but resolves candidate keys from a
// [jwk.Source] at each call. When the token names a KID it tries only that key; otherwise it tries
// every key in the source. Build one with [NewSourcedED25519Verifier].
type SourcedED25519Verifier struct {
	source *jwk.Source[ed25519.PublicKey]
}

// NewSourcedED25519Verifier returns a [jwt.RecipientPlugin] that verifies Ed25519-signed (EdDSA)
// tokens against keys drawn from the source.
//
// See RFC 8032, section 3.3: https://datatracker.ietf.org/doc/html/rfc8032#section-3.3
func NewSourcedED25519Verifier(source *jwk.Source[ed25519.PublicKey]) *SourcedED25519Verifier {
	return &SourcedED25519Verifier{
		source: source,
	}
}

func (verifier *SourcedED25519Verifier) Transform(
	ctx context.Context, header *jwa.JWH, rawToken string,
) ([]byte, error) {
	keys, err := verifier.source.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("(SourcedED25519Verifier.Transform) %w", err)
	}

	for _, key := range keys {
		// A token that names a KID can only match that key; skip the rest.
		if header.KID != "" && key.KID != header.KID {
			continue
		}

		token, err := NewED25519Verifier(key.Key()).Transform(ctx, header, rawToken)
		if err == nil {
			return token, nil
		}

		if !errors.Is(err, ErrInvalidSignature) {
			return nil, fmt.Errorf("(SourcedED25519Verifier.Transform) %w", err)
		}
	}

	return nil, fmt.Errorf("(SourcedED25519Verifier.Transform) %w", ErrInvalidSignature)
}
