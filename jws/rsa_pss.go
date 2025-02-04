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

type RSAPSSPreset struct {
	Hash crypto.Hash
	Alg  jwa.Alg
}

var (
	PS256 = RSAPSSPreset{
		Hash: crypto.SHA256,
		Alg:  jwa.PS256,
	}
	PS384 = RSAPSSPreset{
		Hash: crypto.SHA384,
		Alg:  jwa.PS384,
	}
	PS512 = RSAPSSPreset{
		Hash: crypto.SHA512,
		Alg:  jwa.PS512,
	}
)

type RSAPSSSigner struct {
	secretKey *rsa.PrivateKey

	alg  jwa.Alg
	hash crypto.Hash
}

func (signer *RSAPSSSigner) Header(_ context.Context, header *jwa.JWH) (*jwa.JWH, error) {
	if !header.Alg.Empty() {
		return nil, fmt.Errorf("(RSAPSSSigner.Header) %w: alg field already set", jwt.ErrConflictingHeader)
	}

	header.Alg = signer.alg

	return header, nil
}

func (signer *RSAPSSSigner) Transform(_ context.Context, _ *jwa.JWH, tokenRaw string) (string, error) {
	token, err := jwt.DecodeToken(tokenRaw, &jwt.RawTokenDecoder{})
	if err != nil {
		return "", fmt.Errorf("(RSAPSSSigner.Transform) split token: %w", err)
	}

	hasher := signer.hash.New()
	hasher.Write(token.Bytes())

	signature, err := rsa.SignPSS(rand.Reader, signer.secretKey, signer.hash, hasher.Sum(nil), &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
	})
	if err != nil {
		return "", fmt.Errorf("(RSAPSSSigner.Transform) %w", err)
	}

	return jwt.SignedToken{
		Header:    token.Header,
		Payload:   token.Payload,
		Signature: base64.RawURLEncoding.EncodeToString(signature),
	}.String(), nil
}

// NewRSAPSSSigner creates a new jwt.ProducerPlugin for a signed token using RSASSA-PSS.
//
// A key of size 2048 bits or larger MUST be used with this algorithm.
//
// Use any of the RSAPSSPreset constants to configure the signing parameters.
//   - PS256: RSASSA-PSS using SHA-384 and MGF1 with SHA-256
//   - PS384: RSASSA-PSS using SHA-384 and MGF1 with SHA-384
//   - PS512: RSASSA-PSS using SHA-512 and MGF1 with SHA-512
//
// https://datatracker.ietf.org/doc/html/rfc7518#section-3.5
func NewRSAPSSSigner(secretKey *rsa.PrivateKey, preset RSAPSSPreset) *RSAPSSSigner {
	return &RSAPSSSigner{
		secretKey: secretKey,
		alg:       preset.Alg,
		hash:      preset.Hash,
	}
}

type RSAPSSVerifier struct {
	publicKey *rsa.PublicKey

	alg  jwa.Alg
	hash crypto.Hash
}

func (verifier *RSAPSSVerifier) Transform(_ context.Context, header *jwa.JWH, rawToken string) ([]byte, error) {
	if header.Alg != verifier.alg {
		return nil, fmt.Errorf(
			"(RSAPSSVerifier.Transform) %w: invalid algorithm %s, expected %s",
			jwt.ErrMismatchRecipientPlugin, header.Alg, verifier.alg,
		)
	}

	token, err := jwt.DecodeToken(rawToken, &jwt.SignedTokenDecoder{})
	if err != nil {
		return nil, fmt.Errorf("(RSAPSSVerifier.Transform) split token: %w", err)
	}

	unsignedToken := jwt.RawToken{Header: token.Header, Payload: token.Payload}

	hasher := verifier.hash.New()
	hasher.Write(unsignedToken.Bytes())

	sigBytes, err := base64.RawURLEncoding.DecodeString(token.Signature)
	if err != nil {
		return nil, fmt.Errorf("(RSAPSSVerifier.Transform) decode signature: %w", err)
	}

	err = rsa.VerifyPSS(verifier.publicKey, verifier.hash, hasher.Sum(nil), sigBytes, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
	})
	if err != nil {
		if errors.Is(err, rsa.ErrVerification) {
			return nil, errors.Join(fmt.Errorf("(RSAVerifier.Transform) %w", ErrInvalidSignature), err)
		}

		return nil, fmt.Errorf("(RSAVerifier.Transform) %w", err)
	}

	decoded, err := base64.RawURLEncoding.DecodeString(token.Payload)
	if err != nil {
		return nil, fmt.Errorf("(RSAPSSVerifier.Transform) decode payload: %w", err)
	}

	return decoded, nil
}

// NewRSAPSSVerifier creates a new jwt.RecipientPlugin for a signed token using RSASSA-PSS.
//
// A key of size 2048 bits or larger MUST be used with this algorithm.
//
// Use any of the RSAPSSPreset constants to configure the signing parameters.
//   - PS256: RSASSA-PSS using SHA-384 and MGF1 with SHA-256
//   - PS384: RSASSA-PSS using SHA-384 and MGF1 with SHA-384
//   - PS512: RSASSA-PSS using SHA-512 and MGF1 with SHA-512
//
// https://datatracker.ietf.org/doc/html/rfc7518#section-3.5
func NewRSAPSSVerifier(publicKey *rsa.PublicKey, preset RSAPSSPreset) *RSAPSSVerifier {
	return &RSAPSSVerifier{
		publicKey: publicKey,
		alg:       preset.Alg,
		hash:      preset.Hash,
	}
}

type SourcedRSAPSSSigner struct {
	source *jwk.Source[*rsa.PrivateKey]
	preset RSAPSSPreset
}

func (signer *SourcedRSAPSSSigner) Header(ctx context.Context, header *jwa.JWH) (*jwa.JWH, error) {
	key, err := signer.source.Get(ctx, header.KID)
	if err != nil {
		return nil, fmt.Errorf("(SourcedRSAPSSSigner.Header) %w", err)
	}

	// If the KID was not set, update it.
	if header.KID == "" {
		header.KID = key.KID
	}

	return NewRSAPSSSigner(key.Key(), signer.preset).Header(ctx, header)
}

func (signer *SourcedRSAPSSSigner) Transform(ctx context.Context, header *jwa.JWH, rawToken string) (string, error) {
	key, err := signer.source.Get(ctx, header.KID)
	if err != nil {
		return "", fmt.Errorf("(SourcedRSAPSSSigner.Transform) %w", err)
	}

	return NewRSAPSSSigner(key.Key(), signer.preset).Transform(ctx, header, rawToken)
}

// NewSourcedRSAPSSSigner creates a new jwt.ProducerPlugin for a signed token using RSASSA-PSS.
//
// A key of size 2048 bits or larger MUST be used with this algorithm.
//
// Use any of the RSAPSSPreset constants to configure the signing parameters.
//   - PS256: RSASSA-PSS using SHA-384 and MGF1 with SHA-256
//   - PS384: RSASSA-PSS using SHA-384 and MGF1 with SHA-384
//   - PS512: RSASSA-PSS using SHA-512 and MGF1 with SHA-512
//
// https://datatracker.ietf.org/doc/html/rfc7518#section-3.5
func NewSourcedRSAPSSSigner(source *jwk.Source[*rsa.PrivateKey], preset RSAPSSPreset) *SourcedRSAPSSSigner {
	return &SourcedRSAPSSSigner{
		source: source,
		preset: preset,
	}
}

type SourcedRSAPSSVerifier struct {
	source *jwk.Source[*rsa.PublicKey]
	preset RSAPSSPreset
}

func (verifier *SourcedRSAPSSVerifier) Transform(
	ctx context.Context, header *jwa.JWH, rawToken string,
) ([]byte, error) {
	keys, err := verifier.source.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("(SourcedRSAPSSVerifier.Transform) %w", err)
	}

	for _, key := range keys {
		// If a KID is set, no need to try with every key.
		if header.KID != "" && key.KID != header.KID {
			continue
		}

		token, err := NewRSAPSSVerifier(key.Key(), verifier.preset).Transform(ctx, header, rawToken)
		if err == nil {
			return token, nil
		}

		if !errors.Is(err, ErrInvalidSignature) {
			return nil, fmt.Errorf("(SourcedRSAPSSVerifier.Transform) %w", err)
		}
	}

	return nil, fmt.Errorf("(SourcedRSAPSSVerifier.Transform) %w", ErrInvalidSignature)
}

// NewSourcedRSAPSSVerifier creates a new jwt.RecipientPlugin for a signed token using RSASSA-PSS.
//
// A key of size 2048 bits or larger MUST be used with this algorithm.
//
// Use any of the RSAPSSPreset constants to configure the signing parameters.
//   - PS256: RSASSA-PSS using SHA-384 and MGF1 with SHA-256
//   - PS384: RSASSA-PSS using SHA-384 and MGF1 with SHA-384
//   - PS512: RSASSA-PSS using SHA-512 and MGF1 with SHA-512
//
// https://datatracker.ietf.org/doc/html/rfc7518#section-3.5
func NewSourcedRSAPSSVerifier(source *jwk.Source[*rsa.PublicKey], preset RSAPSSPreset) *SourcedRSAPSSVerifier {
	return &SourcedRSAPSSVerifier{
		source: source,
		preset: preset,
	}
}
