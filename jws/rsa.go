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

// An RSAPreset bundles the hash and algorithm identifier for one RSASSA-PKCS1-v1_5 signing scheme.
// Pass one of the exported presets to the RSA constructors rather than assembling the fields by hand.
type RSAPreset struct {
	Hash crypto.Hash
	Alg  jwa.Alg
}

var (
	// RS256 is RSASSA-PKCS1-v1_5 using SHA-256.
	RS256 = RSAPreset{
		Hash: crypto.SHA256,
		Alg:  jwa.RS256,
	}
	// RS384 is RSASSA-PKCS1-v1_5 using SHA-384.
	RS384 = RSAPreset{
		Hash: crypto.SHA384,
		Alg:  jwa.RS384,
	}
	// RS512 is RSASSA-PKCS1-v1_5 using SHA-512.
	RS512 = RSAPreset{
		Hash: crypto.SHA512,
		Alg:  jwa.RS512,
	}
)

// An RSASigner signs tokens with RSASSA-PKCS1-v1_5 as a [jwt.ProducerPlugin]. Build one with
// [NewRSASigner].
type RSASigner struct {
	secretKey *rsa.PrivateKey

	alg  jwa.Alg
	hash crypto.Hash
}

// NewRSASigner returns a [jwt.ProducerPlugin] that signs tokens with RSASSA-PKCS1-v1_5, using the
// hash carried by the preset (one of [RS256], [RS384], [RS512]). The key must be at least 2048 bits.
//
// See RFC 7518, section 3.3: https://datatracker.ietf.org/doc/html/rfc7518#section-3.3
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

	err := checkRSAPrivateKey(signer.secretKey)
	if err != nil {
		return nil, fmt.Errorf("(RSASigner.Header) %w", err)
	}

	header.Alg = signer.alg

	return header, nil
}

func (signer *RSASigner) Transform(_ context.Context, _ *jwa.JWH, tokenRaw string) (string, error) {
	// Re-check on the signing path too: a sourced signer re-resolves its key here without going
	// back through Header, so this is the only guard that actually gates every signature.
	err := checkRSAPrivateKey(signer.secretKey)
	if err != nil {
		return "", fmt.Errorf("(RSASigner.Transform) %w", err)
	}

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

// An RSAVerifier verifies RSASSA-PKCS1-v1_5-signed tokens as a [jwt.RecipientPlugin]. Build one with
// [NewRSAVerifier]. It returns [ErrInvalidSignature] when the signature does not match.
type RSAVerifier struct {
	publicKey *rsa.PublicKey

	alg  jwa.Alg
	hash crypto.Hash
}

// NewRSAVerifier returns a [jwt.RecipientPlugin] that verifies RSASSA-PKCS1-v1_5-signed tokens,
// using the hash carried by the preset (one of [RS256], [RS384], [RS512]).
//
// See RFC 7518, section 3.3: https://datatracker.ietf.org/doc/html/rfc7518#section-3.3
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

	err := checkRSAPublicKey(verifier.publicKey)
	if err != nil {
		return nil, fmt.Errorf("(RSAVerifier.Transform) %w", err)
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

// A SourcedRSASigner signs like an [RSASigner] but resolves its key from a [jwk.Source] at each
// call, so the plugin follows key rotation instead of pinning one key. Build one with
// [NewSourcedRSASigner].
type SourcedRSASigner struct {
	source *jwk.Source[*rsa.PrivateKey]
	preset RSAPreset
}

// NewSourcedRSASigner returns a [jwt.ProducerPlugin] that signs tokens with RSASSA-PKCS1-v1_5,
// drawing the key from the source for the header's KID. The preset (one of [RS256], [RS384],
// [RS512]) selects the hash, and the key must be at least 2048 bits.
//
// See RFC 7518, section 3.3: https://datatracker.ietf.org/doc/html/rfc7518#section-3.3
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

	// Stamp the resolved key's ID into the header so recipients can select it for verification.
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

// A SourcedRSAVerifier verifies like an [RSAVerifier] but resolves candidate keys from a
// [jwk.Source] at each call. When the token names a KID it tries only that key; otherwise it tries
// every key in the source. Build one with [NewSourcedRSAVerifier].
type SourcedRSAVerifier struct {
	source *jwk.Source[*rsa.PublicKey]
	preset RSAPreset
}

// NewSourcedRSAVerifier returns a [jwt.RecipientPlugin] that verifies RSASSA-PKCS1-v1_5-signed
// tokens against keys drawn from the source. The preset (one of [RS256], [RS384], [RS512]) selects
// the hash.
//
// See RFC 7518, section 3.3: https://datatracker.ietf.org/doc/html/rfc7518#section-3.3
func NewSourcedRSAVerifier(source *jwk.Source[*rsa.PublicKey], preset RSAPreset) *SourcedRSAVerifier {
	return &SourcedRSAVerifier{
		source: source,
		preset: preset,
	}
}

func (verifier *SourcedRSAVerifier) Transform(
	ctx context.Context, header *jwa.JWH, rawToken string,
) ([]byte, error) {
	return verifyFromSource(ctx, verifier.source, header, rawToken, func(key *rsa.PublicKey) jwt.RecipientPlugin {
		return NewRSAVerifier(key, verifier.preset)
	})
}
