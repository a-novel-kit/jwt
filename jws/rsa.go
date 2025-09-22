package jws

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/a-novel-kit/jwt"
	"github.com/a-novel-kit/jwt/jwa"
	"github.com/a-novel-kit/jwt/jwk"
)

type RSAPreset struct {
	Hash crypto.Hash
	Alg  jwa.Alg
}

var (
	RS256 = RSAPreset{
		Hash: crypto.SHA256,
		Alg:  jwa.RS256,
	}
	RS384 = RSAPreset{
		Hash: crypto.SHA384,
		Alg:  jwa.RS384,
	}
	RS512 = RSAPreset{
		Hash: crypto.SHA512,
		Alg:  jwa.RS512,
	}
)

type RSASigner struct {
	secretKey *rsa.PrivateKey

	alg  jwa.Alg
	hash crypto.Hash
}

// NewRSASigner creates a new jwt.ProducerPlugin for a signed token using RSASSA-PKCS1-v1_5.
// A key of size 2048 bits or larger MUST be used with these algorithms.
//
// Use any of the RSAPreset constants to configure the signing parameters.
//   - RS256: RSASSA-PKCS1-v1_5 using SHA-256
//   - RS384: RSASSA-PKCS1-v1_5 using SHA-384
//   - RS512: RSASSA-PKCS1-v1_5 using SHA-512
//
// https://datatracker.ietf.org/doc/html/rfc7518#section-3.3
func NewRSASigner(secretKey *rsa.PrivateKey, preset RSAPreset) *RSASigner {
	return &RSASigner{
		secretKey: secretKey,
		alg:       preset.Alg,
		hash:      preset.Hash,
	}
}

func (signer *RSASigner) Header(_ context.Context, header *jwa.JWH) (*jwa.JWH, error) {
	if !header.Alg.Empty() {
		return nil, fmt.Errorf("(RSASigner.Header) %w: alg field already set", jwt.ErrConflictingHeader)
	}

	header.Alg = signer.alg

	return header, nil
}

func (signer *RSASigner) Transform(_ context.Context, _ *jwa.JWH, tokenRaw string) (string, error) {
	token, err := jwt.DecodeToken(tokenRaw, &jwt.RawTokenDecoder{})
	if err != nil {
		return "", fmt.Errorf("(RSASigner.Transform) split token: %w", err)
	}

	hasher := signer.hash.New()
	hasher.Write(token.Bytes())

	signature, err := rsa.SignPKCS1v15(rand.Reader, signer.secretKey, signer.hash, hasher.Sum(nil))
	if err != nil {
		return "", fmt.Errorf("(rsaSigner.Sign) %w", err)
	}

	return jwt.SignedToken{
		Header:    token.Header,
		Payload:   token.Payload,
		Signature: base64.RawURLEncoding.EncodeToString(signature),
	}.String(), nil
}

type RSAVerifier struct {
	publicKey *rsa.PublicKey

	alg  jwa.Alg
	hash crypto.Hash
}

// NewRSAVerifier creates a new jwt.RecipientPlugin for a signed token using RSASSA-PKCS1-v1_5.
// A key of size 2048 bits or larger MUST be used with these algorithms.
//
// Use any of the RSAPreset constants to configure the signing parameters.
//   - RS256: RSASSA-PKCS1-v1_5 using SHA-256
//   - RS384: RSASSA-PKCS1-v1_5 using SHA-384
//   - RS512: RSASSA-PKCS1-v1_5 using SHA-512
//
// https://datatracker.ietf.org/doc/html/rfc7518#section-3.3
func NewRSAVerifier(publicKey *rsa.PublicKey, preset RSAPreset) *RSAVerifier {
	return &RSAVerifier{
		publicKey: publicKey,
		alg:       preset.Alg,
		hash:      preset.Hash,
	}
}

func (verifier *RSAVerifier) Transform(_ context.Context, header *jwa.JWH, rawToken string) ([]byte, error) {
	if header.Alg != verifier.alg {
		return nil, fmt.Errorf(
			"(RSAVerifier.Transform) %w: invalid algorithm %s, expected %s",
			jwt.ErrMismatchRecipientPlugin, header.Alg, verifier.alg,
		)
	}

	token, err := jwt.DecodeToken(rawToken, &jwt.SignedTokenDecoder{})
	if err != nil {
		return nil, fmt.Errorf("(RSAVerifier.Transform) split token: %w", err)
	}

	unsignedToken := jwt.RawToken{Header: token.Header, Payload: token.Payload}

	hasher := verifier.hash.New()
	hasher.Write(unsignedToken.Bytes())

	sigBytes, err := base64.RawURLEncoding.DecodeString(token.Signature)
	if err != nil {
		return nil, fmt.Errorf("(RSAVerifier.Transform) decode signature: %w", err)
	}

	err = rsa.VerifyPKCS1v15(verifier.publicKey, verifier.hash, hasher.Sum(nil), sigBytes)
	if err != nil {
		if errors.Is(err, rsa.ErrVerification) {
			return nil, errors.Join(fmt.Errorf("(RSAVerifier.Transform) %w", ErrInvalidSignature), err)
		}

		return nil, fmt.Errorf("(RSAVerifier.Transform) %w", err)
	}

	decoded, err := base64.RawURLEncoding.DecodeString(token.Payload)
	if err != nil {
		return nil, fmt.Errorf("(RSAVerifier.Transform) decode payload: %w", err)
	}

	return decoded, nil
}

type SourcedRSASigner struct {
	source *jwk.Source[*rsa.PrivateKey]
	preset RSAPreset
}

// NewSourcedRSASigner creates a new jwt.ProducerPlugin for a signed token using RSASSA-PKCS1-v1_5.
// A key of size 2048 bits or larger MUST be used with these algorithms.
//
// Use any of the RSAPreset constants to configure the signing parameters.
//   - RS256: RSASSA-PKCS1-v1_5 using SHA-256
//   - RS384: RSASSA-PKCS1-v1_5 using SHA-384
//   - RS512: RSASSA-PKCS1-v1_5 using SHA-512
//
// https://datatracker.ietf.org/doc/html/rfc7518#section-3.3
func NewSourcedRSASigner(source *jwk.Source[*rsa.PrivateKey], preset RSAPreset) *SourcedRSASigner {
	return &SourcedRSASigner{
		source: source,
		preset: preset,
	}
}

func (signer *SourcedRSASigner) Header(ctx context.Context, header *jwa.JWH) (*jwa.JWH, error) {
	key, err := signer.source.Get(ctx, header.KID)
	if err != nil {
		return nil, fmt.Errorf("(SourcedRSASigner.Header) %w", err)
	}

	// If the KID was not set, update it.
	if header.KID == "" {
		header.KID = key.KID
	}

	return NewRSASigner(key.Key(), signer.preset).Header(ctx, header)
}

func (signer *SourcedRSASigner) Transform(ctx context.Context, header *jwa.JWH, rawToken string) (string, error) {
	key, err := signer.source.Get(ctx, header.KID)
	if err != nil {
		return "", fmt.Errorf("(SourcedRSASigner.Transform) %w", err)
	}

	return NewRSASigner(key.Key(), signer.preset).Transform(ctx, header, rawToken)
}

type SourcedRSAVerifier struct {
	source *jwk.Source[*rsa.PublicKey]
	preset RSAPreset
}

// NewSourcedRSAVerifier creates a new jwt.RecipientPlugin for a signed token using RSASSA-PKCS1-v1_5.
// A key of size 2048 bits or larger MUST be used with these algorithms.
//
// Use any of the RSAPreset constants to configure the signing parameters.
//   - RS256: RSASSA-PKCS1-v1_5 using SHA-256
//   - RS384: RSASSA-PKCS1-v1_5 using SHA-384
//   - RS512: RSASSA-PKCS1-v1_5 using SHA-512
//
// https://datatracker.ietf.org/doc/html/rfc7518#section-3.3
func NewSourcedRSAVerifier(source *jwk.Source[*rsa.PublicKey], preset RSAPreset) *SourcedRSAVerifier {
	return &SourcedRSAVerifier{
		source: source,
		preset: preset,
	}
}

func (verifier *SourcedRSAVerifier) Transform(
	ctx context.Context, header *jwa.JWH, rawToken string,
) ([]byte, error) {
	keys, err := verifier.source.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("(SourcedRSAVerifier.Transform) %w", err)
	}

	for _, key := range keys {
		// If a KID is set, no need to try with every key.
		if header.KID != "" && key.KID != header.KID {
			continue
		}

		token, err := NewRSAVerifier(key.Key(), verifier.preset).Transform(ctx, header, rawToken)
		if err == nil {
			return token, nil
		}

		if !errors.Is(err, ErrInvalidSignature) {
			return nil, fmt.Errorf("(SourcedRSAVerifier.Transform) %w", err)
		}
	}

	return nil, fmt.Errorf("(SourcedRSAVerifier.Transform) %w", ErrInvalidSignature)
}
