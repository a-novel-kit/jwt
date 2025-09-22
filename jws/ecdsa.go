package jws

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"

	"github.com/a-novel-kit/jwt"
	"github.com/a-novel-kit/jwt/jwa"
	"github.com/a-novel-kit/jwt/jwk"
)

type ECDSAPreset struct {
	Hash crypto.Hash
	Alg  jwa.Alg
	Crv  elliptic.Curve
}

var (
	ES256 = ECDSAPreset{
		Hash: crypto.SHA256,
		Alg:  jwa.ES256,
		Crv:  elliptic.P256(),
	}
	ES384 = ECDSAPreset{
		Hash: crypto.SHA384,
		Alg:  jwa.ES384,
		Crv:  elliptic.P384(),
	}
	ES512 = ECDSAPreset{
		Hash: crypto.SHA512,
		Alg:  jwa.ES512,
		Crv:  elliptic.P521(),
	}
)

func inferECDSAKeySize(params *elliptic.CurveParams) int {
	curveBits := params.BitSize
	keyBytes := curveBits / 8

	if curveBits%8 > 0 {
		keyBytes++
	}

	return keyBytes
}

type ECDSASigner struct {
	secretKey *ecdsa.PrivateKey

	alg  jwa.Alg
	hash crypto.Hash
	crv  elliptic.Curve
}

// NewECDSASigner creates a new jwt.ProducerPlugin for a signed token using ECDSA.
//
// Use any of the ECDSAPreset constants to configure the signing parameters.
//   - ES256: ECDSA using P-256 and SHA-256
//   - ES384: ECDSA using P-384 and SHA-384
//   - ES512: ECDSA using P-521 and SHA-512
//
// https://datatracker.ietf.org/doc/html/rfc7518#section-3.4
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

	// We serialize the outputs (r and s) into big-endian byte arrays
	// padded with zeros on the left to make sure the sizes work out.
	// Output must be 2*keyBytes long.
	signature := make([]byte, 2*keyBytes)
	r.FillBytes(signature[0:keyBytes]) // r is assigned to the first half of output.
	s.FillBytes(signature[keyBytes:])  // s is assigned to the second half of output.

	return jwt.SignedToken{
		Header:    token.Header,
		Payload:   token.Payload,
		Signature: base64.RawURLEncoding.EncodeToString(signature),
	}.String(), nil
}

type ECDSAVerifier struct {
	publicKey *ecdsa.PublicKey
	alg       jwa.Alg
	hash      crypto.Hash
}

// NewECDSAVerifier creates a new jwt.RecipientPlugin for a signed token using ECDSA.
//
// Use any of the ECDSAPreset constants to configure the verification parameters.
//   - ES256: ECDSA using P-256 and SHA-256
//   - ES384: ECDSA using P-384 and SHA-384
//   - ES512: ECDSA using P-521 and SHA-512
//
// https://datatracker.ietf.org/doc/html/rfc7518#section-3.4
func NewECDSAVerifier(publicKey *ecdsa.PublicKey, preset ECDSAPreset) *ECDSAVerifier {
	return &ECDSAVerifier{
		publicKey: publicKey,
		alg:       preset.Alg,
		hash:      preset.Hash,
	}
}

func (verifier *ECDSAVerifier) Transform(_ context.Context, header *jwa.JWH, rawToken string) ([]byte, error) {
	if header.Alg != verifier.alg {
		return nil, fmt.Errorf(
			"(ECDSAVerifier.Transform) %w: invalid algorithm %s, expected %s",
			jwt.ErrMismatchRecipientPlugin, header.Alg, verifier.alg,
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

type SourcedECDSASigner struct {
	source *jwk.Source[*ecdsa.PrivateKey]
	preset ECDSAPreset
}

// NewSourcedECDSASigner creates a new jwt.ProducerPlugin for a signed token using ECDSA.
//
// Use any of the ECDSAPreset constants to configure the signing parameters.
//   - ES256: ECDSA using P-256 and SHA-256
//   - ES384: ECDSA using P-384 and SHA-384
//   - ES512: ECDSA using P-521 and SHA-512
//
// https://datatracker.ietf.org/doc/html/rfc7518#section-3.4
func NewSourcedECDSASigner(source *jwk.Source[*ecdsa.PrivateKey], preset ECDSAPreset) *SourcedECDSASigner {
	return &SourcedECDSASigner{
		source: source,
		preset: preset,
	}
}

func (signer *SourcedECDSASigner) Header(ctx context.Context, header *jwa.JWH) (*jwa.JWH, error) {
	key, err := signer.source.Get(ctx, header.KID)
	if err != nil {
		return nil, fmt.Errorf("(SourcedECDSASigner.Header) %w", err)
	}

	// If the KID was not set, update it.
	if header.KID == "" {
		header.KID = key.KID
	}

	return NewECDSASigner(key.Key(), signer.preset).Header(ctx, header)
}

func (signer *SourcedECDSASigner) Transform(ctx context.Context, header *jwa.JWH, rawToken string) (string, error) {
	key, err := signer.source.Get(ctx, header.KID)
	if err != nil {
		return "", fmt.Errorf("(SourcedECDSASigner.Transform) %w", err)
	}

	return NewECDSASigner(key.Key(), signer.preset).Transform(ctx, header, rawToken)
}

type SourcedECDSAVerifier struct {
	source *jwk.Source[*ecdsa.PublicKey]
	preset ECDSAPreset
}

// NewSourcedECDSAVerifier creates a new jwt.RecipientPlugin for a signed token using ECDSA.
//
// Use any of the ECDSAPreset constants to configure the verification parameters.
//   - ES256: ECDSA using P-256 and SHA-256
//   - ES384: ECDSA using P-384 and SHA-384
//   - ES512: ECDSA using P-521 and SHA-512
//
// https://datatracker.ietf.org/doc/html/rfc7518#section-3.4
func NewSourcedECDSAVerifier(source *jwk.Source[*ecdsa.PublicKey], preset ECDSAPreset) *SourcedECDSAVerifier {
	return &SourcedECDSAVerifier{
		source: source,
		preset: preset,
	}
}

func (verifier *SourcedECDSAVerifier) Transform(ctx context.Context, header *jwa.JWH, rawToken string) ([]byte, error) {
	keys, err := verifier.source.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("(SourcedECDSAVerifier.Transform) %w", err)
	}

	for _, key := range keys {
		// If a KID is set, no need to try with every key.
		if header.KID != "" && key.KID != header.KID {
			continue
		}

		token, err := NewECDSAVerifier(key.Key(), verifier.preset).Transform(ctx, header, rawToken)
		if err == nil {
			return token, nil
		}

		if !errors.Is(err, ErrInvalidSignature) {
			return nil, fmt.Errorf("(SourcedECDSAVerifier.Transform) %w", err)
		}
	}

	return nil, fmt.Errorf("(SourcedECDSAVerifier.Transform) %w", ErrInvalidSignature)
}
