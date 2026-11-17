package jws

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/a-novel-kit/jwt/v2"
	"github.com/a-novel-kit/jwt/v2/jwa"
	"github.com/a-novel-kit/jwt/v2/jwk"
)

// An ECDSAPreset describes an ECDSA signing scheme. Pass one of the exported presets to the ECDSA
// constructors.
type ECDSAPreset struct {
	// Hash digests the signing input.
	Hash crypto.Hash
	// Alg is the signature algorithm.
	Alg jwa.Alg
	// Crv is the curve the key must live on.
	Crv elliptic.Curve
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
	return (params.BitSize + 7) / 8
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
	return signHeader(header, signer.alg, checkECDSAPrivateKey(signer.secretKey, signer.crv))
}

func (signer *ECDSASigner) Transform(_ context.Context, _ *jwa.JWH, rawToken string) (string, error) {
	return signToken(rawToken, checkECDSAPrivateKey(signer.secretKey, signer.crv), signer.sign)
}

// sign returns the ECDSA signature over signingInput. JWS encodes it as the fixed-width
// concatenation R || S, each value big-endian and left-padded to the curve's coordinate size
// (RFC 7518 §3.4). The ASN.1 DER form of ecdsa.SignASN1 does not interoperate.
func (signer *ECDSASigner) sign(signingInput []byte) ([]byte, error) {
	hasher := signer.hash.New()
	hasher.Write(signingInput)

	r, s, err := ecdsa.Sign(rand.Reader, signer.secretKey, hasher.Sum(nil))
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}

	keyBytes := inferECDSAKeySize(signer.secretKey.Params())

	signature := make([]byte, 2*keyBytes)
	r.FillBytes(signature[:keyBytes])
	s.FillBytes(signature[keyBytes:])

	return signature, nil
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
	return verifyToken(header, verifier.alg, checkECDSAKey(verifier.publicKey, verifier.crv), rawToken, verifier.verify)
}

// verify checks the R || S signature over signingInput, as [ECDSASigner.sign] encodes it.
func (verifier *ECDSAVerifier) verify(signingInput, signature []byte) error {
	keyBytes := inferECDSAKeySize(verifier.publicKey.Params())
	if len(signature) != 2*keyBytes {
		return fmt.Errorf("%w: invalid signature size", ErrInvalidSignature)
	}

	r := new(big.Int).SetBytes(signature[:keyBytes])
	s := new(big.Int).SetBytes(signature[keyBytes:])

	hasher := verifier.hash.New()
	hasher.Write(signingInput)

	if !ecdsa.Verify(verifier.publicKey, hasher.Sum(nil), r, s) {
		return ErrInvalidSignature
	}

	return nil
}

// checkECDSAKey fails unless key lives on crv. RFC 7518 §3.4 binds each ES* algorithm to one curve,
// so a plugin holding a key on another curve enforces no ES* algorithm at all: it reports the
// misconfiguration instead of failing every signature.
func checkECDSAKey(key *ecdsa.PublicKey, crv elliptic.Curve) error {
	if key == nil || key.Curve != crv {
		return fmt.Errorf("%w: ECDSA key does not live on the curve of the preset", jwt.ErrInvalidSecretKey)
	}

	return nil
}

// checkECDSAPrivateKey applies checkECDSAKey to a private key's public half, rejecting a nil key
// first so the dereference is safe.
func checkECDSAPrivateKey(key *ecdsa.PrivateKey, crv elliptic.Curve) error {
	if key == nil {
		return fmt.Errorf("%w: nil ECDSA key", jwt.ErrInvalidSecretKey)
	}

	return checkECDSAKey(&key.PublicKey, crv)
}

// consumeECDSA binds [jwk.ConsumeECDSA] to the algorithm and curve of preset.
func consumeECDSA(preset ECDSAPreset) keyPair[*ecdsa.PrivateKey, *ecdsa.PublicKey] {
	jwkPreset := jwk.ECDSAPreset{Alg: preset.Alg, Curve: preset.Crv}

	return func(key *jwa.JWK) (*jwk.Key[*ecdsa.PrivateKey], *jwk.Key[*ecdsa.PublicKey], error) {
		return jwk.ConsumeECDSA(key, jwkPreset)
	}
}

// A SourcedECDSASigner signs like an [ECDSASigner] but resolves its key from a [jwk.Source] at each
// call, so the plugin follows key rotation. Build one with [NewSourcedECDSASigner].
type SourcedECDSASigner struct {
	sourcedSigner[*ecdsa.PrivateKey]
}

// NewSourcedECDSASigner returns a [jwt.ProducerPlugin] that signs tokens with ECDSA, drawing the key
// from the source for the header's KID. The preset (one of [ES256], [ES384], [ES512]) selects the
// curve and hash.
//
// See RFC 7518, section 3.4: https://datatracker.ietf.org/doc/html/rfc7518#section-3.4
func NewSourcedECDSASigner(source *jwk.Source, preset ECDSAPreset) *SourcedECDSASigner {
	newSigner := func(key *ecdsa.PrivateKey) jwt.ProducerPlugin { return NewECDSASigner(key, preset) }

	return &SourcedECDSASigner{newSourcedSigner(source, privateHalf(consumeECDSA(preset)), newSigner)}
}

// A SourcedECDSAVerifier verifies like an [ECDSAVerifier] but resolves candidate keys from a
// [jwk.Source] at each call. When the token names a KID, it tries only that key. Otherwise it tries
// every key in the source. Build one with [NewSourcedECDSAVerifier].
type SourcedECDSAVerifier struct {
	sourcedVerifier[*ecdsa.PublicKey]
}

// NewSourcedECDSAVerifier returns a [jwt.RecipientPlugin] that verifies ECDSA-signed tokens against
// keys drawn from the source. The preset (one of [ES256], [ES384], [ES512]) selects the curve and
// hash.
//
// See RFC 7518, section 3.4: https://datatracker.ietf.org/doc/html/rfc7518#section-3.4
func NewSourcedECDSAVerifier(source *jwk.Source, preset ECDSAPreset) *SourcedECDSAVerifier {
	newVerifier := func(key *ecdsa.PublicKey) jwt.RecipientPlugin { return NewECDSAVerifier(key, preset) }

	return &SourcedECDSAVerifier{newSourcedVerifier(source, publicHalf(consumeECDSA(preset)), newVerifier)}
}
