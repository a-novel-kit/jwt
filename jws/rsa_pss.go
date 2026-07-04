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

// An RSAPSSPreset bundles the hash and algorithm identifier for one RSASSA-PSS signing scheme.
// RSASSA-PSS uses the same hash for the digest and for MGF1. Pass one of the exported presets to the
// RSA-PSS constructors rather than assembling the fields by hand.
type RSAPSSPreset struct {
	Hash crypto.Hash
	Alg  jwa.Alg
}

var (
	// PS256 is RSASSA-PSS using SHA-256 and MGF1 with SHA-256.
	PS256 = RSAPSSPreset{
		Hash: crypto.SHA256,
		Alg:  jwa.PS256,
	}
	// PS384 is RSASSA-PSS using SHA-384 and MGF1 with SHA-384.
	PS384 = RSAPSSPreset{
		Hash: crypto.SHA384,
		Alg:  jwa.PS384,
	}
	// PS512 is RSASSA-PSS using SHA-512 and MGF1 with SHA-512.
	PS512 = RSAPSSPreset{
		Hash: crypto.SHA512,
		Alg:  jwa.PS512,
	}
)

// An RSAPSSSigner signs tokens with RSASSA-PSS as a [jwt.ProducerPlugin]. Build one with
// [NewRSAPSSSigner].
type RSAPSSSigner struct {
	secretKey *rsa.PrivateKey

	alg  jwa.Alg
	hash crypto.Hash
}

// NewRSAPSSSigner returns a [jwt.ProducerPlugin] that signs tokens with RSASSA-PSS, using the hash
// carried by the preset (one of [PS256], [PS384], [PS512]). The key must be at least 2048 bits.
//
// See RFC 7518, section 3.5: https://datatracker.ietf.org/doc/html/rfc7518#section-3.5
func NewRSAPSSSigner(secretKey *rsa.PrivateKey, preset RSAPSSPreset) *RSAPSSSigner {
	return &RSAPSSSigner{
		secretKey: secretKey,
		alg:       preset.Alg,
		hash:      preset.Hash,
	}
}

func (signer *RSAPSSSigner) Header(_ context.Context, header *jwa.JWH) (*jwa.JWH, error) {
	if !header.Alg.Empty() {
		return nil, fmt.Errorf("(RSAPSSSigner.Header) %w: alg field already set", jwt.ErrConflictingHeader)
	}

	err := checkRSAPrivateKey(signer.secretKey)
	if err != nil {
		return nil, fmt.Errorf("(RSAPSSSigner.Header) %w", err)
	}

	header.Alg = signer.alg

	return header, nil
}

func (signer *RSAPSSSigner) Transform(_ context.Context, _ *jwa.JWH, tokenRaw string) (string, error) {
	// Re-check on the signing path too: a sourced signer re-resolves its key here without going
	// back through Header, so this is the only guard that actually gates every signature.
	err := checkRSAPrivateKey(signer.secretKey)
	if err != nil {
		return "", fmt.Errorf("(RSAPSSSigner.Transform) %w", err)
	}

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

// An RSAPSSVerifier verifies RSASSA-PSS-signed tokens as a [jwt.RecipientPlugin]. Build one with
// [NewRSAPSSVerifier]. It returns [ErrInvalidSignature] when the signature does not match.
type RSAPSSVerifier struct {
	publicKey *rsa.PublicKey

	alg  jwa.Alg
	hash crypto.Hash
}

// NewRSAPSSVerifier returns a [jwt.RecipientPlugin] that verifies RSASSA-PSS-signed tokens, using
// the hash carried by the preset (one of [PS256], [PS384], [PS512]).
//
// See RFC 7518, section 3.5: https://datatracker.ietf.org/doc/html/rfc7518#section-3.5
func NewRSAPSSVerifier(publicKey *rsa.PublicKey, preset RSAPSSPreset) *RSAPSSVerifier {
	return &RSAPSSVerifier{
		publicKey: publicKey,
		alg:       preset.Alg,
		hash:      preset.Hash,
	}
}

func (verifier *RSAPSSVerifier) Transform(_ context.Context, header *jwa.JWH, rawToken string) ([]byte, error) {
	if header.Alg != verifier.alg {
		return nil, fmt.Errorf(
			"(RSAPSSVerifier.Transform) %w: invalid algorithm %s, expected %s",
			jwt.ErrMismatchRecipientPlugin, header.Alg, verifier.alg,
		)
	}

	err := checkRSAPublicKey(verifier.publicKey)
	if err != nil {
		return nil, fmt.Errorf("(RSAPSSVerifier.Transform) %w", err)
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
			return nil, errors.Join(fmt.Errorf("(RSAPSSVerifier.Transform) %w", ErrInvalidSignature), err)
		}

		return nil, fmt.Errorf("(RSAPSSVerifier.Transform) %w", err)
	}

	decoded, err := base64.RawURLEncoding.DecodeString(token.Payload)
	if err != nil {
		return nil, fmt.Errorf("(RSAPSSVerifier.Transform) decode payload: %w", err)
	}

	return decoded, nil
}

// A SourcedRSAPSSSigner signs like an [RSAPSSSigner] but resolves its key from a [jwk.Source] at
// each call, so the plugin follows key rotation instead of pinning one key. Build one with
// [NewSourcedRSAPSSSigner].
type SourcedRSAPSSSigner struct {
	source *jwk.Source[*rsa.PrivateKey]
	preset RSAPSSPreset
}

// NewSourcedRSAPSSSigner returns a [jwt.ProducerPlugin] that signs tokens with RSASSA-PSS, drawing
// the key from the source for the header's KID. The preset (one of [PS256], [PS384], [PS512])
// selects the hash, and the key must be at least 2048 bits.
//
// See RFC 7518, section 3.5: https://datatracker.ietf.org/doc/html/rfc7518#section-3.5
func NewSourcedRSAPSSSigner(source *jwk.Source[*rsa.PrivateKey], preset RSAPSSPreset) *SourcedRSAPSSSigner {
	return &SourcedRSAPSSSigner{
		source: source,
		preset: preset,
	}
}

func (signer *SourcedRSAPSSSigner) Header(ctx context.Context, header *jwa.JWH) (*jwa.JWH, error) {
	key, err := signer.source.Get(ctx, header.KID)
	if err != nil {
		return nil, fmt.Errorf("(SourcedRSAPSSSigner.Header) %w", err)
	}

	// Stamp the resolved key's ID into the header so recipients can select it for verification.
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

// A SourcedRSAPSSVerifier verifies like an [RSAPSSVerifier] but resolves candidate keys from a
// [jwk.Source] at each call. When the token names a KID it tries only that key; otherwise it tries
// every key in the source. Build one with [NewSourcedRSAPSSVerifier].
type SourcedRSAPSSVerifier struct {
	source *jwk.Source[*rsa.PublicKey]
	preset RSAPSSPreset
}

// NewSourcedRSAPSSVerifier returns a [jwt.RecipientPlugin] that verifies RSASSA-PSS-signed tokens
// against keys drawn from the source. The preset (one of [PS256], [PS384], [PS512]) selects the hash.
//
// See RFC 7518, section 3.5: https://datatracker.ietf.org/doc/html/rfc7518#section-3.5
func NewSourcedRSAPSSVerifier(source *jwk.Source[*rsa.PublicKey], preset RSAPSSPreset) *SourcedRSAPSSVerifier {
	return &SourcedRSAPSSVerifier{
		source: source,
		preset: preset,
	}
}

func (verifier *SourcedRSAPSSVerifier) Transform(
	ctx context.Context, header *jwa.JWH, rawToken string,
) ([]byte, error) {
	return verifyFromSource(ctx, verifier.source, header, rawToken, func(key *rsa.PublicKey) jwt.RecipientPlugin {
		return NewRSAPSSVerifier(key, verifier.preset)
	})
}
