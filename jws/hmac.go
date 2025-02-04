package jws

import (
	"context"
	"crypto"
	"crypto/hmac"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/a-novel-kit/jwt"
	"github.com/a-novel-kit/jwt/jwa"
	"github.com/a-novel-kit/jwt/jwk"
)

type HMACPreset struct {
	Hash crypto.Hash
	Alg  jwa.Alg
}

var (
	HS256 = HMACPreset{
		Hash: crypto.SHA256,
		Alg:  jwa.HS256,
	}
	HS384 = HMACPreset{
		Hash: crypto.SHA384,
		Alg:  jwa.HS384,
	}
	HS512 = HMACPreset{
		Hash: crypto.SHA512,
		Alg:  jwa.HS512,
	}
)

type HMACSigner struct {
	secretKey []byte

	alg  jwa.Alg
	hash crypto.Hash
}

func (signer *HMACSigner) Header(_ context.Context, header *jwa.JWH) (*jwa.JWH, error) {
	if !header.Alg.Empty() {
		return nil, fmt.Errorf("(HMACSigner.Header) %w: alg field already set", jwt.ErrConflictingHeader)
	}

	header.Alg = signer.alg

	return header, nil
}

func (signer *HMACSigner) Transform(_ context.Context, _ *jwa.JWH, tokenRaw string) (string, error) {
	token, err := jwt.DecodeToken(tokenRaw, &jwt.RawTokenDecoder{})
	if err != nil {
		return "", fmt.Errorf("(HMACSigner.Transform) split token: %w", err)
	}

	hasher := hmac.New(signer.hash.New, signer.secretKey)
	hasher.Write(token.Bytes())

	signature := hasher.Sum(nil)
	return jwt.SignedToken{
		Header:    token.Header,
		Payload:   token.Payload,
		Signature: base64.RawURLEncoding.EncodeToString(signature),
	}.String(), nil
}

// NewHMACSigner creates a new jwt.ProducerPlugin for a signed token using HMAC with SHA-2.
//
// Use any of the HMACPreset constants to configure the signing parameters.
//   - HS256: HMAC using SHA-256
//   - HS384: HMAC using SHA-384
//   - HS512: HMAC using SHA-512
//
// https://datatracker.ietf.org/doc/html/rfc7518#section-3.2
func NewHMACSigner(secretKey []byte, preset HMACPreset) *HMACSigner {
	return &HMACSigner{
		secretKey: secretKey,
		alg:       preset.Alg,
		hash:      preset.Hash,
	}
}

type HMACVerifier struct {
	secretKey []byte

	alg  jwa.Alg
	hash crypto.Hash
}

func (verifier *HMACVerifier) Transform(_ context.Context, header *jwa.JWH, rawToken string) ([]byte, error) {
	if header.Alg != verifier.alg {
		return nil, fmt.Errorf(
			"(HMACVerifier.Transform) %w: invalid algorithm %s, expected %s",
			jwt.ErrMismatchRecipientPlugin, header.Alg, verifier.alg,
		)
	}

	token, err := jwt.DecodeToken(rawToken, &jwt.SignedTokenDecoder{})
	if err != nil {
		return nil, fmt.Errorf("(HMACVerifier.Transform) split token: %w", err)
	}

	unsignedToken := jwt.RawToken{Header: token.Header, Payload: token.Payload}

	sigBytes, err := base64.RawURLEncoding.DecodeString(token.Signature)
	if err != nil {
		return nil, fmt.Errorf("(HMACVerifier.Transform) decode signature: %w", err)
	}

	hasher := hmac.New(verifier.hash.New, verifier.secretKey)
	hasher.Write(unsignedToken.Bytes())

	if !hmac.Equal(sigBytes, hasher.Sum(nil)) {
		return nil, fmt.Errorf("(HMACVerifier.Transform) %w", ErrInvalidSignature)
	}

	decoded, err := base64.RawURLEncoding.DecodeString(token.Payload)
	if err != nil {
		return nil, fmt.Errorf("(HMACVerifier.Transform) decode payload: %w", err)
	}

	return decoded, nil
}

// NewHMACVerifier creates a new jwt.RecipientPlugin for a signed token using HMAC with SHA-2.
//
// Use any of the HMACPreset constants to configure the signing parameters.
//   - HS256: HMAC using SHA-256
//   - HS384: HMAC using SHA-384
//   - HS512: HMAC using SHA-512
//
// https://datatracker.ietf.org/doc/html/rfc7518#section-3.2
func NewHMACVerifier(secretKey []byte, preset HMACPreset) *HMACVerifier {
	return &HMACVerifier{
		secretKey: secretKey,
		alg:       preset.Alg,
		hash:      preset.Hash,
	}
}

type SourceHMACSigner struct {
	source *jwk.Source[[]byte]
	preset HMACPreset
}

func (signer *SourceHMACSigner) Header(ctx context.Context, header *jwa.JWH) (*jwa.JWH, error) {
	key, err := signer.source.Get(ctx, header.KID)
	if err != nil {
		return nil, fmt.Errorf("(SourceHMACSigner.Header) %w", err)
	}

	// If the KID was not set, update it.
	if header.KID == "" {
		header.KID = key.KID
	}

	return NewHMACSigner(key.Key(), signer.preset).Header(ctx, header)
}

func (signer *SourceHMACSigner) Transform(ctx context.Context, header *jwa.JWH, rawToken string) (string, error) {
	key, err := signer.source.Get(ctx, header.KID)
	if err != nil {
		return "", fmt.Errorf("(SourceHMACSigner.Transform) %w", err)
	}

	return NewHMACSigner(key.Key(), signer.preset).Transform(ctx, header, rawToken)
}

// NewSourceHMACSigner creates a new jwt.ProducerPlugin for a signed token using HMAC with SHA-2.
//
// Use any of the HMACPreset constants to configure the signing parameters.
//   - HS256: HMAC using SHA-256
//   - HS384: HMAC using SHA-384
//   - HS512: HMAC using SHA-512
//
// https://datatracker.ietf.org/doc/html/rfc7518#section-3.2
func NewSourcedHMACSigner(source *jwk.Source[[]byte], preset HMACPreset) *SourceHMACSigner {
	return &SourceHMACSigner{
		source: source,
		preset: preset,
	}
}

type SourceHMACVerifier struct {
	source *jwk.Source[[]byte]
	preset HMACPreset
}

func (verifier *SourceHMACVerifier) Transform(ctx context.Context, header *jwa.JWH, rawToken string) ([]byte, error) {
	keys, err := verifier.source.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("(SourceHMACVerifier.Transform) %w", err)
	}

	for _, key := range keys {
		// If a KID is set, no need to try with every key.
		if header.KID != "" && key.KID != header.KID {
			continue
		}

		token, err := NewHMACVerifier(key.Key(), verifier.preset).Transform(ctx, header, rawToken)
		if err == nil {
			return token, nil
		}

		if !errors.Is(err, ErrInvalidSignature) {
			return nil, fmt.Errorf("(SourceHMACVerifier.Transform) %w", err)
		}
	}

	return nil, fmt.Errorf("(SourceHMACVerifier.Transform) %w", ErrInvalidSignature)
}

// NewSourceHMACVerifier creates a new jwt.RecipientPlugin for a signed token using HMAC with SHA-2.
//
// Use any of the HMACPreset constants to configure the signing parameters.
//   - HS256: HMAC using SHA-256
//   - HS384: HMAC using SHA-384
//   - HS512: HMAC using SHA-512
//
// https://datatracker.ietf.org/doc/html/rfc7518#section-3.2
func NewSourcedHMACVerifier(source *jwk.Source[[]byte], preset HMACPreset) *SourceHMACVerifier {
	return &SourceHMACVerifier{
		source: source,
		preset: preset,
	}
}
