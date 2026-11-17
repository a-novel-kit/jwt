package jws

import (
	"context"
	"crypto/mldsa"
	"errors"
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

// errNilMLDSAKey reports a plugin built without an ML-DSA key.
var errNilMLDSAKey = fmt.Errorf("%w: nil ML-DSA key", jwt.ErrInvalidSecretKey)

// An MLDSASigner signs tokens with the post-quantum ML-DSA scheme as a [jwt.ProducerPlugin]. Build
// one with [NewMLDSASigner].
type MLDSASigner struct {
	secretKey *mldsa.PrivateKey
	alg       jwa.Alg
}

// NewMLDSASigner returns a [jwt.ProducerPlugin] that signs tokens with ML-DSA. The key's parameter
// set selects the algorithm: ML-DSA-44, ML-DSA-65, or ML-DSA-87.
//
// See RFC 9964, section 5: https://datatracker.ietf.org/doc/html/rfc9964#section-5
func NewMLDSASigner(secretKey *mldsa.PrivateKey) *MLDSASigner {
	signer := &MLDSASigner{secretKey: secretKey}
	if secretKey != nil {
		signer.alg = mldsaAlg(secretKey.PublicKey().Parameters())
	}

	return signer
}

func (signer *MLDSASigner) Header(_ context.Context, header *jwa.JWH) (*jwa.JWH, error) {
	return signHeader(header, signer.alg, signer.checkKey())
}

func (signer *MLDSASigner) Transform(_ context.Context, _ *jwa.JWH, rawToken string) (string, error) {
	return signToken(rawToken, signer.checkKey(), func(signingInput []byte) ([]byte, error) {
		// Nil options sign the message itself with an empty context, as RFC 9964 requires.
		return signer.secretKey.Sign(nil, signingInput, nil)
	})
}

func (signer *MLDSASigner) checkKey() error {
	if signer.secretKey == nil {
		return errNilMLDSAKey
	}

	return nil
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
	// The key's parameter set fixes the algorithm, so the key is checked before the header.
	if verifier.publicKey == nil {
		return nil, errNilMLDSAKey
	}

	alg := mldsaAlg(verifier.publicKey.Parameters())

	return verifyToken(header, alg, nil, rawToken, func(signingInput, signature []byte) error {
		err := mldsa.Verify(verifier.publicKey, signingInput, signature, nil)
		if err != nil {
			return errors.Join(ErrInvalidSignature, err)
		}

		return nil
	})
}

// A SourcedMLDSASigner signs like an [MLDSASigner] but resolves its key from a [jwk.Source] at each
// call, so the plugin follows key rotation. Without a KID it signs with the first ML-DSA key the
// source lists, whatever its level. Build one with [NewSourcedMLDSASigner].
type SourcedMLDSASigner struct {
	sourcedSigner[*mldsa.PrivateKey]
}

// NewSourcedMLDSASigner returns a [jwt.ProducerPlugin] that signs tokens with ML-DSA, drawing the key
// from the source for the header's KID.
//
// See RFC 9964, section 5: https://datatracker.ietf.org/doc/html/rfc9964#section-5
func NewSourcedMLDSASigner(source *jwk.Source) *SourcedMLDSASigner {
	newSigner := func(key *mldsa.PrivateKey) jwt.ProducerPlugin { return NewMLDSASigner(key) }

	return &SourcedMLDSASigner{newSourcedSigner(source, privateHalf(jwk.ConsumeMLDSA), newSigner)}
}

// A SourcedMLDSAVerifier verifies like an [MLDSAVerifier] but resolves candidate keys from a
// [jwk.Source] at each call. When the token names a KID, it tries only that key. Otherwise it tries
// every key in the source bound to the token's algorithm. Build one with [NewSourcedMLDSAVerifier].
type SourcedMLDSAVerifier struct {
	sourced sourcedVerifier[*mldsa.PublicKey]
}

// NewSourcedMLDSAVerifier returns a [jwt.RecipientPlugin] that verifies ML-DSA-signed tokens against
// keys drawn from the source.
//
// See RFC 9964, section 5: https://datatracker.ietf.org/doc/html/rfc9964#section-5
func NewSourcedMLDSAVerifier(source *jwk.Source) *SourcedMLDSAVerifier {
	newVerifier := func(key *mldsa.PublicKey) jwt.RecipientPlugin { return NewMLDSAVerifier(key) }

	return &SourcedMLDSAVerifier{newSourcedVerifier(source, publicHalf(jwk.ConsumeMLDSA), newVerifier)}
}

func (verifier *SourcedMLDSAVerifier) Transform(ctx context.Context, header *jwa.JWH, rawToken string) ([]byte, error) {
	// A source can hold keys of every ML-DSA level. The token's algorithm picks the ones that can
	// verify it, and a token under any other algorithm belongs to another plugin.
	switch header.Alg {
	case jwa.MLDSA44, jwa.MLDSA65, jwa.MLDSA87:
	default:
		return nil, fmt.Errorf(
			"%w: invalid algorithm %s, expected an ML-DSA algorithm", jwt.ErrMismatchRecipientPlugin, header.Alg,
		)
	}

	// Keys of another level are skipped like keys of another family.
	decode := func(key *jwa.JWK) (*mldsa.PublicKey, error) {
		if key.Alg != header.Alg {
			return nil, fmt.Errorf("%w: key is for %s", jwk.ErrJWKMismatch, key.Alg)
		}

		return verifier.sourced.keys.Decode(key)
	}

	return verifyFromSource(ctx, verifier.sourced.source, header, rawToken, decode, verifier.sourced.newVerifier)
}
