package jws

import (
	"context"
	"crypto/mldsa"
	"encoding/base64"
	"fmt"

	"github.com/a-novel-kit/jwt/v2"
	"github.com/a-novel-kit/jwt/v2/jwa"
	"github.com/a-novel-kit/jwt/v2/jwk"
)

// mldsaAlg returns the JWS algorithm of an ML-DSA parameter set. Each set maps to exactly one, so a
// key fixes the algorithm it signs and verifies under.
func mldsaAlg(params mldsa.Parameters) jwa.Alg {
	switch params {
	case mldsa.MLDSA44():
		return jwa.MLDSA44
	case mldsa.MLDSA65():
		return jwa.MLDSA65
	case mldsa.MLDSA87():
		return jwa.MLDSA87
	default:
		return ""
	}
}

// An MLDSASigner signs tokens with the post-quantum ML-DSA scheme as a [jwt.ProducerPlugin]. Build
// one with [NewMLDSASigner].
type MLDSASigner struct {
	secretKey *mldsa.PrivateKey
}

// NewMLDSASigner returns a [jwt.ProducerPlugin] that signs tokens with ML-DSA. The key's parameter
// set selects the algorithm: ML-DSA-44, ML-DSA-65, or ML-DSA-87.
//
// See RFC 9964, section 5: https://datatracker.ietf.org/doc/html/rfc9964#section-5
func NewMLDSASigner(secretKey *mldsa.PrivateKey) *MLDSASigner {
	return &MLDSASigner{
		secretKey: secretKey,
	}
}

func (signer *MLDSASigner) Header(_ context.Context, header *jwa.JWH) (*jwa.JWH, error) {
	if !header.Alg.Empty() {
		return nil, fmt.Errorf("(MLDSASigner.Header) %w: alg field already set", jwt.ErrConflictingHeader)
	}

	if signer.secretKey == nil {
		return nil, fmt.Errorf("(MLDSASigner.Header) %w: nil ML-DSA key", jwt.ErrInvalidSecretKey)
	}

	header.Alg = mldsaAlg(signer.secretKey.PublicKey().Parameters())

	return header, nil
}

func (signer *MLDSASigner) Transform(_ context.Context, _ *jwa.JWH, rawToken string) (string, error) {
	token, err := jwt.DecodeToken(rawToken, &jwt.RawTokenDecoder{})
	if err != nil {
		return "", fmt.Errorf("(MLDSASigner.Transform) split token: %w", err)
	}

	// Nil options sign the message itself with an empty context, as RFC 9964 requires.
	signature, err := signer.secretKey.Sign(nil, token.Bytes(), nil)
	if err != nil {
		return "", fmt.Errorf("(MLDSASigner.Transform) %w", err)
	}

	return jwt.SignedToken{
		Header:    token.Header,
		Payload:   token.Payload,
		Signature: base64.RawURLEncoding.EncodeToString(signature),
	}.String(), nil
}

// An MLDSAVerifier verifies ML-DSA-signed tokens as a [jwt.RecipientPlugin]. It accepts only the
// algorithm its key's parameter set maps to. Build one with [NewMLDSAVerifier]. It returns
// [ErrInvalidSignature] when the signature does not match.
type MLDSAVerifier struct {
	publicKey *mldsa.PublicKey
}

// NewMLDSAVerifier returns a [jwt.RecipientPlugin] that verifies ML-DSA-signed tokens.
//
// See RFC 9964, section 5: https://datatracker.ietf.org/doc/html/rfc9964#section-5
func NewMLDSAVerifier(publicKey *mldsa.PublicKey) *MLDSAVerifier {
	return &MLDSAVerifier{
		publicKey: publicKey,
	}
}

func (verifier *MLDSAVerifier) Transform(_ context.Context, header *jwa.JWH, rawToken string) ([]byte, error) {
	if verifier.publicKey == nil {
		return nil, fmt.Errorf("(MLDSAVerifier.Transform) %w: nil ML-DSA key", jwt.ErrInvalidSecretKey)
	}

	alg := mldsaAlg(verifier.publicKey.Parameters())
	if header.Alg != alg {
		return nil, fmt.Errorf(
			"(MLDSAVerifier.Transform) %w: invalid algorithm %s, expected %s",
			jwt.ErrMismatchRecipientPlugin, header.Alg, alg,
		)
	}

	token, err := jwt.DecodeToken(rawToken, &jwt.SignedTokenDecoder{})
	if err != nil {
		return nil, fmt.Errorf("(MLDSAVerifier.Transform) split source: %w", err)
	}

	unsignedToken := jwt.RawToken{Header: token.Header, Payload: token.Payload}

	sigBytes, err := base64.RawURLEncoding.DecodeString(token.Signature)
	if err != nil {
		return nil, fmt.Errorf("(MLDSAVerifier.Transform) decode signature: %w", err)
	}

	err = mldsa.Verify(verifier.publicKey, unsignedToken.Bytes(), sigBytes, nil)
	if err != nil {
		return nil, fmt.Errorf("(MLDSAVerifier.Transform) %w", ErrInvalidSignature)
	}

	decoded, err := base64.RawURLEncoding.DecodeString(token.Payload)
	if err != nil {
		return nil, fmt.Errorf("(MLDSAVerifier.Transform) decode payload: %w", err)
	}

	return decoded, nil
}

// sourcedMLDSAPublic decodes a raw JSON Web Key into an ML-DSA public key for verification under
// alg, skipping keys of another parameter set and any that carry private material.
func sourcedMLDSAPublic(alg jwa.Alg) keyDecoder[*mldsa.PublicKey] {
	return func(key *jwa.JWK) (*mldsa.PublicKey, error) {
		if key.Alg != alg {
			return nil, fmt.Errorf("%w: key is for %s", jwk.ErrJWKMismatch, key.Alg)
		}

		privateKey, publicKey, err := jwk.ConsumeMLDSA(key)
		if err != nil {
			return nil, err
		}

		if privateKey != nil {
			return nil, fmt.Errorf("%w: source exposes a private key", jwk.ErrJWKMismatch)
		}

		return publicKey.Key(), nil
	}
}

// sourcedMLDSAPrivate decodes a raw JSON Web Key into an ML-DSA private key for signing.
func sourcedMLDSAPrivate() keyDecoder[*mldsa.PrivateKey] {
	return func(key *jwa.JWK) (*mldsa.PrivateKey, error) {
		privateKey, _, err := jwk.ConsumeMLDSA(key)
		if err != nil {
			return nil, err
		}

		if privateKey == nil {
			return nil, fmt.Errorf("%w", jwk.ErrJWKMismatch)
		}

		return privateKey.Key(), nil
	}
}

// A SourcedMLDSASigner signs like an [MLDSASigner] but resolves its key from a [jwk.Source] at each
// call, so the plugin follows key rotation. Without a KID it signs with the first ML-DSA key the
// source lists, whatever its level. Build one with [NewSourcedMLDSASigner].
type SourcedMLDSASigner struct {
	source *jwk.Source
}

// NewSourcedMLDSASigner returns a [jwt.ProducerPlugin] that signs tokens with ML-DSA, drawing the key
// from the source for the header's KID.
//
// See RFC 9964, section 5: https://datatracker.ietf.org/doc/html/rfc9964#section-5
func NewSourcedMLDSASigner(source *jwk.Source) *SourcedMLDSASigner {
	return &SourcedMLDSASigner{
		source: source,
	}
}

func (signer *SourcedMLDSASigner) Header(ctx context.Context, header *jwa.JWH) (*jwa.JWH, error) {
	key, kid, err := signFromSource(ctx, signer.source, header.KID, sourcedMLDSAPrivate())
	if err != nil {
		return nil, fmt.Errorf("(SourcedMLDSASigner.Header) %w", err)
	}

	// Stamp the resolved key's ID into the header so recipients can select it for verification.
	if header.KID == "" {
		header.KID = kid
	}

	return NewMLDSASigner(key).Header(ctx, header)
}

func (signer *SourcedMLDSASigner) Transform(ctx context.Context, header *jwa.JWH, rawToken string) (string, error) {
	key, _, err := signFromSource(ctx, signer.source, header.KID, sourcedMLDSAPrivate())
	if err != nil {
		return "", fmt.Errorf("(SourcedMLDSASigner.Transform) %w", err)
	}

	return NewMLDSASigner(key).Transform(ctx, header, rawToken)
}

// A SourcedMLDSAVerifier verifies like an [MLDSAVerifier] but resolves candidate keys from a
// [jwk.Source] at each call. When the token names a KID it tries only that key; otherwise it tries
// every key in the source bound to the token's algorithm. Build one with [NewSourcedMLDSAVerifier].
type SourcedMLDSAVerifier struct {
	source *jwk.Source
}

// NewSourcedMLDSAVerifier returns a [jwt.RecipientPlugin] that verifies ML-DSA-signed tokens against
// keys drawn from the source.
//
// See RFC 9964, section 5: https://datatracker.ietf.org/doc/html/rfc9964#section-5
func NewSourcedMLDSAVerifier(source *jwk.Source) *SourcedMLDSAVerifier {
	return &SourcedMLDSAVerifier{
		source: source,
	}
}

func (verifier *SourcedMLDSAVerifier) Transform(ctx context.Context, header *jwa.JWH, rawToken string) ([]byte, error) {
	// A source can hold keys of every ML-DSA level. The token's algorithm picks the ones that can
	// verify it, and a token under any other algorithm belongs to another plugin.
	switch header.Alg {
	case jwa.MLDSA44, jwa.MLDSA65, jwa.MLDSA87:
	default:
		return nil, fmt.Errorf(
			"(SourcedMLDSAVerifier.Transform) %w: invalid algorithm %s, expected an ML-DSA algorithm",
			jwt.ErrMismatchRecipientPlugin, header.Alg,
		)
	}

	return verifyFromSource(ctx, verifier.source, header, rawToken, sourcedMLDSAPublic(header.Alg),
		func(key *mldsa.PublicKey) jwt.RecipientPlugin {
			return NewMLDSAVerifier(key)
		})
}
