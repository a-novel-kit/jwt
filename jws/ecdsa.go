package jws

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math/big"

	"github.com/a-novel-kit/jwt/v2"
	"github.com/a-novel-kit/jwt/v2/jwa"
	"github.com/a-novel-kit/jwt/v2/jwk"
)

// An ECDSAPreset bundles the curve, hash, and algorithm identifier for one ECDSA signing scheme.
// Pass one of the exported presets to the ECDSA constructors.
type ECDSAPreset struct {
	Hash crypto.Hash
	Alg  jwa.Alg
	Crv  elliptic.Curve
}

var (
	// ES256 is ECDSA using the P-256 curve and SHA-256.
	ES256 = ECDSAPreset{
		Hash: crypto.SHA256,
		Alg:  jwa.ES256,
		Crv:  elliptic.P256(),
	}
	// ES384 is ECDSA using the P-384 curve and SHA-384.
	ES384 = ECDSAPreset{
		Hash: crypto.SHA384,
		Alg:  jwa.ES384,
		Crv:  elliptic.P384(),
	}
	// ES512 is ECDSA using the P-521 curve and SHA-512.
	ES512 = ECDSAPreset{
		Hash: crypto.SHA512,
		Alg:  jwa.ES512,
		Crv:  elliptic.P521(),
	}
)

// inferECDSAKeySize returns the byte width of a coordinate on the given curve, rounding up when the
// bit size is not a multiple of eight. JWS pads both signature halves to this width.
func inferECDSAKeySize(params *elliptic.CurveParams) int {
	curveBits := params.BitSize
	keyBytes := curveBits / 8

	if curveBits%8 > 0 {
		keyBytes++
	}

	return keyBytes
}

// An ECDSASigner signs tokens with ECDSA as a [jwt.ProducerPlugin]. Build one with [NewECDSASigner].
type ECDSASigner struct {
	secretKey *ecdsa.PrivateKey

	alg  jwa.Alg
	hash crypto.Hash
	crv  elliptic.Curve
}

// NewECDSASigner returns a [jwt.ProducerPlugin] that signs tokens with ECDSA, using the curve and
// hash carried by the preset (one of [ES256], [ES384], [ES512]).
//
// See RFC 7518, section 3.4: https://datatracker.ietf.org/doc/html/rfc7518#section-3.4
func NewECDSASigner(secretKey *ecdsa.PrivateKey, preset ECDSAPreset) *ECDSASigner {
	return &ECDSASigner{
		secretKey: secretKey,
		alg:       preset.Alg,
		hash:      preset.Hash,
		crv:       preset.Crv,
	}
}

func (signer *ECDSASigner) Header(_ context.Context, header *jwa.JWH) (*jwa.JWH, error) {
	if !header.Alg.Empty() {
		return nil, fmt.Errorf("(ECDSASigner.Header) %w: alg field already set", jwt.ErrConflictingHeader)
	}

	header.Alg = signer.alg

	if signer.secretKey.Curve.Params().Name != signer.crv.Params().Name {
		return nil, fmt.Errorf("(ECDSASigner.Header) %w: key size and hash size mismatch", jwt.ErrInvalidSecretKey)
	}

	return header, nil
}

func (signer *ECDSASigner) Transform(_ context.Context, _ *jwa.JWH, rawToken string) (string, error) {
	token, err := jwt.DecodeToken(rawToken, &jwt.RawTokenDecoder{})
	if err != nil {
		return "", fmt.Errorf("(ECDSASigner.Transform) split source: %w", err)
	}

	hasher := signer.hash.New()
	hasher.Write(token.Bytes())

	r, s, err := ecdsa.Sign(rand.Reader, signer.secretKey, hasher.Sum(nil))
	if err != nil {
		return "", fmt.Errorf("(ECDSASigner.Transform) %w", err)
	}

	keyBytes := inferECDSAKeySize(signer.secretKey.Params())

	// JWS encodes an ECDSA signature as the fixed-width concatenation R || S, each value big-endian
	// and left-padded to the curve's coordinate size — not the ASN.1 DER that crypto/ecdsa returns.
	signature := make([]byte, 2*keyBytes)
	r.FillBytes(signature[0:keyBytes])
	s.FillBytes(signature[keyBytes:])

	return jwt.SignedToken{
		Header:    token.Header,
		Payload:   token.Payload,
		Signature: base64.RawURLEncoding.EncodeToString(signature),
	}.String(), nil
}

// An ECDSAVerifier verifies ECDSA-signed tokens as a [jwt.RecipientPlugin]. Build one with
// [NewECDSAVerifier]. It returns [ErrInvalidSignature] when the signature does not match.
type ECDSAVerifier struct {
	publicKey *ecdsa.PublicKey
	alg       jwa.Alg
	hash      crypto.Hash
	crv       elliptic.Curve
}

// NewECDSAVerifier returns a [jwt.RecipientPlugin] that verifies ECDSA-signed tokens, using the
// curve and hash carried by the preset (one of [ES256], [ES384], [ES512]).
//
// See RFC 7518, section 3.4: https://datatracker.ietf.org/doc/html/rfc7518#section-3.4
func NewECDSAVerifier(publicKey *ecdsa.PublicKey, preset ECDSAPreset) *ECDSAVerifier {
	return &ECDSAVerifier{
		publicKey: publicKey,
		alg:       preset.Alg,
		hash:      preset.Hash,
		crv:       preset.Crv,
	}
}

func (verifier *ECDSAVerifier) Transform(_ context.Context, header *jwa.JWH, rawToken string) ([]byte, error) {
	if header.Alg != verifier.alg {
		return nil, fmt.Errorf(
			"(ECDSAVerifier.Transform) %w: invalid algorithm %s, expected %s",
			jwt.ErrMismatchRecipientPlugin, header.Alg, verifier.alg,
		)
	}

	// RFC 7518 §3.4 binds the algorithm to the curve, and the signer checks the same thing. An
	// operator who configures ES256 against a P-384 key does not enforce ES256, and matching on alg
	// alone leaves that unsaid — the signature simply fails to verify.
	if verifier.publicKey == nil || verifier.publicKey.Curve != verifier.crv {
		return nil, fmt.Errorf(
			"(ECDSAVerifier.Transform) %w: verification key does not live on the curve %s requires",
			jwt.ErrInvalidSecretKey, verifier.alg,
		)
	}

	token, err := jwt.DecodeToken(rawToken, &jwt.SignedTokenDecoder{})
	if err != nil {
		return nil, fmt.Errorf("(ECDSAVerifier.Transform) split source: %w", err)
	}

	unsignedToken := jwt.RawToken{Header: token.Header, Payload: token.Payload}

	sigBytes, err := base64.RawURLEncoding.DecodeString(token.Signature)
	if err != nil {
		return nil, fmt.Errorf("(ECDSAVerifier.Transform) decode signature: %w", err)
	}

	keyBytes := inferECDSAKeySize(verifier.publicKey.Params())
	if len(sigBytes) != 2*keyBytes {
		return nil, fmt.Errorf("(ECDSAVerifier.Transform) %w: invalid signature size", ErrInvalidSignature)
	}

	r := big.NewInt(0).SetBytes(sigBytes[:keyBytes])
	s := big.NewInt(0).SetBytes(sigBytes[keyBytes:])

	hasher := verifier.hash.New()
	hasher.Write(unsignedToken.Bytes())

	if !ecdsa.Verify(verifier.publicKey, hasher.Sum(nil), r, s) {
		return nil, fmt.Errorf("(ECDSAVerifier.Transform) %w", ErrInvalidSignature)
	}

	decoded, err := base64.RawURLEncoding.DecodeString(token.Payload)
	if err != nil {
		return nil, fmt.Errorf("(ECDSAVerifier.Transform) decode payload: %w", err)
	}

	return decoded, nil
}

// sourcedECDSAPublic decodes a raw JSON Web Key into an ECDSA public key for verification, matching
// only signature keys on the preset's algorithm and curve, skipping any that carry private material.
func sourcedECDSAPublic(preset ECDSAPreset) keyDecoder[*ecdsa.PublicKey] {
	jwkPreset := jwk.ECDSAPreset{Alg: preset.Alg, Curve: preset.Crv}

	return func(key *jwa.JWK) (*ecdsa.PublicKey, error) {
		privateKey, publicKey, err := jwk.ConsumeECDSA(key, jwkPreset)
		if err != nil {
			return nil, err
		}

		if privateKey != nil {
			return nil, fmt.Errorf("%w: source exposes a private key", jwk.ErrJWKMismatch)
		}

		if publicKey == nil {
			return nil, fmt.Errorf("%w", jwk.ErrJWKMismatch)
		}

		return publicKey.Key(), nil
	}
}

// sourcedECDSAPrivate decodes a raw JSON Web Key into an ECDSA private key for signing.
func sourcedECDSAPrivate(preset ECDSAPreset) keyDecoder[*ecdsa.PrivateKey] {
	jwkPreset := jwk.ECDSAPreset{Alg: preset.Alg, Curve: preset.Crv}

	return func(key *jwa.JWK) (*ecdsa.PrivateKey, error) {
		privateKey, _, err := jwk.ConsumeECDSA(key, jwkPreset)
		if err != nil {
			return nil, err
		}

		if privateKey == nil {
			return nil, fmt.Errorf("%w", jwk.ErrJWKMismatch)
		}

		return privateKey.Key(), nil
	}
}

// A SourcedECDSASigner signs like an [ECDSASigner] but resolves its key from a [jwk.Source] at each
// call, so the plugin follows key rotation. Build one with [NewSourcedECDSASigner].
type SourcedECDSASigner struct {
	source *jwk.Source
	preset ECDSAPreset
}

// NewSourcedECDSASigner returns a [jwt.ProducerPlugin] that signs tokens with ECDSA, drawing the key
// from the source for the header's KID. The preset (one of [ES256], [ES384], [ES512]) selects the
// curve and hash.
//
// See RFC 7518, section 3.4: https://datatracker.ietf.org/doc/html/rfc7518#section-3.4
func NewSourcedECDSASigner(source *jwk.Source, preset ECDSAPreset) *SourcedECDSASigner {
	return &SourcedECDSASigner{
		source: source,
		preset: preset,
	}
}

func (signer *SourcedECDSASigner) Header(ctx context.Context, header *jwa.JWH) (*jwa.JWH, error) {
	key, kid, err := signFromSource(ctx, signer.source, header.KID, sourcedECDSAPrivate(signer.preset))
	if err != nil {
		return nil, fmt.Errorf("(SourcedECDSASigner.Header) %w", err)
	}

	// Stamp the resolved key's ID into the header so recipients can select it for verification.
	if header.KID == "" {
		header.KID = kid
	}

	return NewECDSASigner(key, signer.preset).Header(ctx, header)
}

func (signer *SourcedECDSASigner) Transform(ctx context.Context, header *jwa.JWH, rawToken string) (string, error) {
	key, _, err := signFromSource(ctx, signer.source, header.KID, sourcedECDSAPrivate(signer.preset))
	if err != nil {
		return "", fmt.Errorf("(SourcedECDSASigner.Transform) %w", err)
	}

	return NewECDSASigner(key, signer.preset).Transform(ctx, header, rawToken)
}

// A SourcedECDSAVerifier verifies like an [ECDSAVerifier] but resolves candidate keys from a
// [jwk.Source] at each call. When the token names a KID it tries only that key; otherwise it tries
// every key in the source. Build one with [NewSourcedECDSAVerifier].
type SourcedECDSAVerifier struct {
	source *jwk.Source
	preset ECDSAPreset
}

// NewSourcedECDSAVerifier returns a [jwt.RecipientPlugin] that verifies ECDSA-signed tokens against
// keys drawn from the source. The preset (one of [ES256], [ES384], [ES512]) selects the curve and
// hash.
//
// See RFC 7518, section 3.4: https://datatracker.ietf.org/doc/html/rfc7518#section-3.4
func NewSourcedECDSAVerifier(source *jwk.Source, preset ECDSAPreset) *SourcedECDSAVerifier {
	return &SourcedECDSAVerifier{
		source: source,
		preset: preset,
	}
}

func (verifier *SourcedECDSAVerifier) Transform(ctx context.Context, header *jwa.JWH, rawToken string) ([]byte, error) {
	return verifyFromSource(ctx, verifier.source, header, rawToken, sourcedECDSAPublic(verifier.preset),
		func(key *ecdsa.PublicKey) jwt.RecipientPlugin {
			return NewECDSAVerifier(key, verifier.preset)
		})
}
