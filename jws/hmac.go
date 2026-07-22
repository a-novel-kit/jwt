package jws

import (
	"context"
	"crypto"
	"crypto/hmac"
	"encoding/base64"
	"fmt"

	"github.com/a-novel-kit/jwt/v2"
	"github.com/a-novel-kit/jwt/v2/jwa"
	"github.com/a-novel-kit/jwt/v2/jwk"
)

// An HMACPreset bundles the hash and algorithm identifier for one HMAC signing scheme. Pass one of
// the exported presets to the HMAC constructors.
type HMACPreset struct {
	Hash crypto.Hash
	Alg  jwa.Alg
}

var (
	// HS256 is HMAC using SHA-256.
	HS256 = HMACPreset{
		Hash: crypto.SHA256,
		Alg:  jwa.HS256,
	}
	// HS384 is HMAC using SHA-384.
	HS384 = HMACPreset{
		Hash: crypto.SHA384,
		Alg:  jwa.HS384,
	}
	// HS512 is HMAC using SHA-512.
	HS512 = HMACPreset{
		Hash: crypto.SHA512,
		Alg:  jwa.HS512,
	}
)

// An HMACSigner signs tokens with HMAC-SHA-2 as a [jwt.ProducerPlugin]. The same secret is used to
// sign and to verify, so keep it private to the trusted parties. Build one with [NewHMACSigner].
type HMACSigner struct {
	secretKey []byte

	alg  jwa.Alg
	hash crypto.Hash
}

// NewHMACSigner returns a [jwt.ProducerPlugin] that signs tokens with HMAC, using the hash carried
// by the preset (one of [HS256], [HS384], [HS512]).
//
// See RFC 7518, section 3.2: https://datatracker.ietf.org/doc/html/rfc7518#section-3.2
func NewHMACSigner(secretKey []byte, preset HMACPreset) *HMACSigner {
	return &HMACSigner{
		secretKey: secretKey,
		alg:       preset.Alg,
		hash:      preset.Hash,
	}
}

func (signer *HMACSigner) Header(_ context.Context, header *jwa.JWH) (*jwa.JWH, error) {
	if !header.Alg.Empty() {
		return nil, fmt.Errorf("(HMACSigner.Header) %w: alg field already set", jwt.ErrConflictingHeader)
	}

	if len(signer.secretKey) < signer.hash.Size() {
		return nil, fmt.Errorf(
			"(HMACSigner.Header) %w: HMAC key is %d bytes, need at least %d (RFC 7518 §3.2)",
			jwt.ErrInvalidSecretKey, len(signer.secretKey), signer.hash.Size(),
		)
	}

	header.Alg = signer.alg

	return header, nil
}

func (signer *HMACSigner) Transform(_ context.Context, _ *jwa.JWH, tokenRaw string) (string, error) {
	// A sourced signer re-resolves its key here without going back through Header, so this is the
	// guard that gates every signature.
	if len(signer.secretKey) < signer.hash.Size() {
		return "", fmt.Errorf(
			"(HMACSigner.Transform) %w: HMAC key is %d bytes, need at least %d (RFC 7518 §3.2)",
			jwt.ErrInvalidSecretKey, len(signer.secretKey), signer.hash.Size(),
		)
	}

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

// An HMACVerifier verifies HMAC-signed tokens as a [jwt.RecipientPlugin]. Build one with
// [NewHMACVerifier]. It returns [ErrInvalidSignature] when the signature does not match.
type HMACVerifier struct {
	secretKey []byte

	alg  jwa.Alg
	hash crypto.Hash
}

// NewHMACVerifier returns a [jwt.RecipientPlugin] that verifies HMAC-signed tokens, using the hash
// carried by the preset (one of [HS256], [HS384], [HS512]). The secret must match the one used to
// sign.
//
// See RFC 7518, section 3.2: https://datatracker.ietf.org/doc/html/rfc7518#section-3.2
func NewHMACVerifier(secretKey []byte, preset HMACPreset) *HMACVerifier {
	return &HMACVerifier{
		secretKey: secretKey,
		alg:       preset.Alg,
		hash:      preset.Hash,
	}
}

func (verifier *HMACVerifier) Transform(_ context.Context, header *jwa.JWH, rawToken string) ([]byte, error) {
	if header.Alg != verifier.alg {
		return nil, fmt.Errorf(
			"(HMACVerifier.Transform) %w: invalid algorithm %s, expected %s",
			jwt.ErrMismatchRecipientPlugin, header.Alg, verifier.alg,
		)
	}

	if len(verifier.secretKey) < verifier.hash.Size() {
		return nil, fmt.Errorf(
			"(HMACVerifier.Transform) %w: HMAC key is %d bytes, need at least %d (RFC 7518 §3.2)",
			jwt.ErrInvalidSecretKey, len(verifier.secretKey), verifier.hash.Size(),
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

// sourcedHMACKey decodes a raw JSON Web Key into its HMAC secret, matching only keys bound to alg.
// HMAC is symmetric, so the same decoder serves signing and verification.
func sourcedHMACKey(alg jwa.Alg) keyDecoder[[]byte] {
	preset := jwk.HMACPreset{Alg: alg}

	return func(key *jwa.JWK) ([]byte, error) {
		decoded, err := jwk.ConsumeHMAC(key, preset)
		if err != nil {
			return nil, err
		}

		return decoded.Key(), nil
	}
}

// A SourcedHMACSigner signs like an [HMACSigner] but resolves its secret from a [jwk.Source] at each
// call, so the plugin follows key rotation. Build one with [NewSourcedHMACSigner].
type SourcedHMACSigner struct {
	source *jwk.Source
	preset HMACPreset
}

// NewSourcedHMACSigner returns a [jwt.ProducerPlugin] that signs tokens with HMAC, drawing the
// secret from the source for the header's KID. The preset (one of [HS256], [HS384], [HS512])
// selects the hash.
//
// See RFC 7518, section 3.2: https://datatracker.ietf.org/doc/html/rfc7518#section-3.2
func NewSourcedHMACSigner(source *jwk.Source, preset HMACPreset) *SourcedHMACSigner {
	return &SourcedHMACSigner{
		source: source,
		preset: preset,
	}
}

func (signer *SourcedHMACSigner) Header(ctx context.Context, header *jwa.JWH) (*jwa.JWH, error) {
	key, kid, err := signFromSource(ctx, signer.source, header.KID, sourcedHMACKey(signer.preset.Alg))
	if err != nil {
		return nil, fmt.Errorf("(SourcedHMACSigner.Header) %w", err)
	}

	// Stamp the resolved key's ID into the header so recipients can select it for verification.
	if header.KID == "" {
		header.KID = kid
	}

	return NewHMACSigner(key, signer.preset).Header(ctx, header)
}

func (signer *SourcedHMACSigner) Transform(ctx context.Context, header *jwa.JWH, rawToken string) (string, error) {
	key, _, err := signFromSource(ctx, signer.source, header.KID, sourcedHMACKey(signer.preset.Alg))
	if err != nil {
		return "", fmt.Errorf("(SourcedHMACSigner.Transform) %w", err)
	}

	return NewHMACSigner(key, signer.preset).Transform(ctx, header, rawToken)
}

// A SourcedHMACVerifier verifies like an [HMACVerifier] but resolves candidate secrets from a
// [jwk.Source] at each call. When the token names a KID it tries only that secret; otherwise it
// tries every secret in the source. Build one with [NewSourcedHMACVerifier].
type SourcedHMACVerifier struct {
	source *jwk.Source
	preset HMACPreset
}

// NewSourcedHMACVerifier returns a [jwt.RecipientPlugin] that verifies HMAC-signed tokens against
// secrets drawn from the source. The preset (one of [HS256], [HS384], [HS512]) selects the hash.
//
// See RFC 7518, section 3.2: https://datatracker.ietf.org/doc/html/rfc7518#section-3.2
func NewSourcedHMACVerifier(source *jwk.Source, preset HMACPreset) *SourcedHMACVerifier {
	return &SourcedHMACVerifier{
		source: source,
		preset: preset,
	}
}

func (verifier *SourcedHMACVerifier) Transform(ctx context.Context, header *jwa.JWH, rawToken string) ([]byte, error) {
	return verifyFromSource(ctx, verifier.source, header, rawToken, sourcedHMACKey(verifier.preset.Alg),
		func(key []byte) jwt.RecipientPlugin {
			return NewHMACVerifier(key, verifier.preset)
		})
}
