package jws

import (
	"context"
	"crypto/ed25519"
	"fmt"

	"github.com/a-novel-kit/jwt/v2"
	"github.com/a-novel-kit/jwt/v2/jwa"
	"github.com/a-novel-kit/jwt/v2/jwk"
)

// An ED25519Signer signs tokens with the Ed25519 EdDSA scheme as a [jwt.ProducerPlugin]. Build one
// with [NewED25519Signer].
type ED25519Signer struct {
	secretKey ed25519.PrivateKey
	alg       jwa.Alg
}

// NewED25519Signer returns a [jwt.ProducerPlugin] that signs tokens with Ed25519, under the
// fully-specified "Ed25519" algorithm of RFC 9864.
//
// See RFC 8032, section 3.3: https://datatracker.ietf.org/doc/html/rfc8032#section-3.3
func NewED25519Signer(secretKey ed25519.PrivateKey) *ED25519Signer {
	return &ED25519Signer{
		secretKey: secretKey,
		alg:       jwa.Ed25519,
	}
}

// NewEdDSASigner returns a [jwt.ProducerPlugin] that signs like [NewED25519Signer] but labels tokens
// with the "EdDSA" algorithm RFC 9864 deprecates. It serves a rollout in which some verifiers accept
// only that label: every verifier in this package accepts both.
//
// Deprecated: switch to [NewED25519Signer] once every verifier accepts "Ed25519".
func NewEdDSASigner(secretKey ed25519.PrivateKey) *ED25519Signer {
	return &ED25519Signer{
		secretKey: secretKey,
		alg:       jwa.EdDSA,
	}
}

func (signer *ED25519Signer) Header(_ context.Context, header *jwa.JWH) (*jwa.JWH, error) {
	return signHeader(header, signer.alg, checkED25519Key(signer.secretKey, ed25519.PrivateKeySize))
}

func (signer *ED25519Signer) Transform(_ context.Context, _ *jwa.JWH, rawToken string) (string, error) {
	keyErr := checkED25519Key(signer.secretKey, ed25519.PrivateKeySize)

	return signToken(rawToken, keyErr, func(signingInput []byte) ([]byte, error) {
		return ed25519.Sign(signer.secretKey, signingInput), nil
	})
}

// An ED25519Verifier verifies Ed25519-signed tokens as a [jwt.RecipientPlugin]. It accepts the
// "Ed25519" algorithm and the "EdDSA" one RFC 9864 deprecates, which names the same scheme for an
// Ed25519 key. Build one with [NewED25519Verifier]. It returns [ErrInvalidSignature] when the
// signature does not match.
type ED25519Verifier struct {
	publicKey ed25519.PublicKey
}

// NewED25519Verifier returns a [jwt.RecipientPlugin] that verifies Ed25519-signed tokens.
//
// See RFC 8032, section 3.3: https://datatracker.ietf.org/doc/html/rfc8032#section-3.3
func NewED25519Verifier(publicKey ed25519.PublicKey) *ED25519Verifier {
	return &ED25519Verifier{
		publicKey: publicKey,
	}
}

func (verifier *ED25519Verifier) Transform(_ context.Context, header *jwa.JWH, rawToken string) ([]byte, error) {
	alg := jwa.Ed25519
	// RFC 9864 deprecates "EdDSA", which names the same scheme for an Ed25519 key.
	if header.Alg == jwa.EdDSA { //nolint:staticcheck // Still accepted, per RFC 9864.
		alg = header.Alg
	}

	keyErr := checkED25519Key(verifier.publicKey, ed25519.PublicKeySize)

	return verifyToken(header, alg, keyErr, rawToken, func(signingInput, signature []byte) error {
		if !ed25519.Verify(verifier.publicKey, signingInput, signature) {
			return ErrInvalidSignature
		}

		return nil
	})
}

// checkED25519Key fails unless key holds size bytes. crypto/ed25519 panics on a key of any other
// length, so the plugins check it first, as every other family checks its key.
func checkED25519Key[K ed25519.PrivateKey | ed25519.PublicKey](key K, size int) error {
	if len(key) != size {
		return fmt.Errorf("%w: Ed25519 key is %d bytes, need %d", jwt.ErrInvalidSecretKey, len(key), size)
	}

	return nil
}

// A SourcedED25519Signer signs like an [ED25519Signer] but resolves its key from a [jwk.Source] at
// each call, so the plugin follows key rotation. Build one with [NewSourcedED25519Signer].
type SourcedED25519Signer struct {
	sourcedSigner[ed25519.PrivateKey]
}

// NewSourcedED25519Signer returns a [jwt.ProducerPlugin] that signs tokens with Ed25519,
// drawing the key from the source for the header's KID.
//
// See RFC 8032, section 3.3: https://datatracker.ietf.org/doc/html/rfc8032#section-3.3
func NewSourcedED25519Signer(source *jwk.Source) *SourcedED25519Signer {
	return &SourcedED25519Signer{newSourcedSigner(source, privateHalf(jwk.ConsumeED25519), newED25519Signer(jwa.Ed25519))}
}

// NewSourcedEdDSASigner returns a [jwt.ProducerPlugin] that signs like [NewSourcedED25519Signer] but
// labels tokens with the deprecated "EdDSA" algorithm, as [NewEdDSASigner] does.
//
// Deprecated: switch to [NewSourcedED25519Signer] once every verifier accepts "Ed25519".
func NewSourcedEdDSASigner(source *jwk.Source) *SourcedED25519Signer {
	return &SourcedED25519Signer{newSourcedSigner(source, privateHalf(jwk.ConsumeED25519), newED25519Signer(jwa.EdDSA))}
}

// newED25519Signer returns the constructor of single-key Ed25519 signers labeling tokens with alg.
func newED25519Signer(alg jwa.Alg) func(key ed25519.PrivateKey) jwt.ProducerPlugin {
	return func(key ed25519.PrivateKey) jwt.ProducerPlugin {
		return &ED25519Signer{secretKey: key, alg: alg}
	}
}

// A SourcedED25519Verifier verifies like an [ED25519Verifier] but resolves candidate keys from a
// [jwk.Source] at each call. When the token names a KID, it tries only that key. Otherwise it tries
// every key in the source. Build one with [NewSourcedED25519Verifier].
type SourcedED25519Verifier struct {
	sourcedVerifier[ed25519.PublicKey]
}

// NewSourcedED25519Verifier returns a [jwt.RecipientPlugin] that verifies Ed25519-signed tokens
// against keys drawn from the source.
//
// See RFC 8032, section 3.3: https://datatracker.ietf.org/doc/html/rfc8032#section-3.3
func NewSourcedED25519Verifier(source *jwk.Source) *SourcedED25519Verifier {
	newVerifier := func(key ed25519.PublicKey) jwt.RecipientPlugin { return NewED25519Verifier(key) }

	return &SourcedED25519Verifier{newSourcedVerifier(source, publicHalf(jwk.ConsumeED25519), newVerifier)}
}
