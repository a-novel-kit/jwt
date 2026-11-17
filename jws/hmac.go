package jws

import (
	"context"
	"crypto"
	"crypto/hmac"
	"fmt"

	"github.com/a-novel-kit/jwt/v2"
	"github.com/a-novel-kit/jwt/v2/jwa"
	"github.com/a-novel-kit/jwt/v2/jwk"
)

// An HMACPreset describes an HMAC signing scheme. Pass one of the exported presets to the HMAC
// constructors.
type HMACPreset struct {
	// Hash is the hash HMAC runs on.
	Hash crypto.Hash
	// Alg is the signature algorithm.
	Alg jwa.Alg
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
	return signHeader(header, signer.alg, checkHMACKey(signer.secretKey, signer.hash))
}

func (signer *HMACSigner) Transform(_ context.Context, _ *jwa.JWH, rawToken string) (string, error) {
	keyErr := checkHMACKey(signer.secretKey, signer.hash)

	return signToken(rawToken, keyErr, func(signingInput []byte) ([]byte, error) {
		return hmacSum(signer.hash, signer.secretKey, signingInput), nil
	})
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
	keyErr := checkHMACKey(verifier.secretKey, verifier.hash)

	return verifyToken(header, verifier.alg, keyErr, rawToken, func(signingInput, signature []byte) error {
		if !hmac.Equal(signature, hmacSum(verifier.hash, verifier.secretKey, signingInput)) {
			return ErrInvalidSignature
		}

		return nil
	})
}

// hmacSum returns the HMAC of signingInput under key.
func hmacSum(hash crypto.Hash, key, signingInput []byte) []byte {
	hasher := hmac.New(hash.New, key)
	hasher.Write(signingInput)

	return hasher.Sum(nil)
}

// checkHMACKey fails unless key is at least as long as the output of hash, the floor RFC 7518 §3.2
// sets for the HS* algorithms.
func checkHMACKey(key []byte, hash crypto.Hash) error {
	if len(key) < hash.Size() {
		return fmt.Errorf(
			"%w: HMAC key is %d bytes, need at least %d (RFC 7518 §3.2)",
			jwt.ErrInvalidSecretKey, len(key), hash.Size(),
		)
	}

	return nil
}

// consumeHMAC decodes a raw JSON Web Key into its HMAC secret, matching only keys bound to alg.
// HMAC is symmetric, so the same decoder serves signing and verification.
func consumeHMAC(alg jwa.Alg) keyDecoder[[]byte] {
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
	*sourcedSigner[[]byte]
}

// NewSourcedHMACSigner returns a [jwt.ProducerPlugin] that signs tokens with HMAC, drawing the
// secret from the source for the header's KID. The preset (one of [HS256], [HS384], [HS512])
// selects the hash.
//
// See RFC 7518, section 3.2: https://datatracker.ietf.org/doc/html/rfc7518#section-3.2
func NewSourcedHMACSigner(source *jwk.Source, preset HMACPreset) *SourcedHMACSigner {
	newSigner := func(key []byte) jwt.ProducerPlugin { return NewHMACSigner(key, preset) }

	return &SourcedHMACSigner{newSourcedSigner(source, consumeHMAC(preset.Alg), newSigner)}
}

// A SourcedHMACVerifier verifies like an [HMACVerifier] but resolves candidate secrets from a
// [jwk.Source] at each call. When the token names a KID, it tries only that secret. Otherwise
// it tries every secret in the source. Build one with [NewSourcedHMACVerifier].
type SourcedHMACVerifier struct {
	*sourcedVerifier[[]byte]
}

// NewSourcedHMACVerifier returns a [jwt.RecipientPlugin] that verifies HMAC-signed tokens against
// secrets drawn from the source. The preset (one of [HS256], [HS384], [HS512]) selects the hash.
//
// See RFC 7518, section 3.2: https://datatracker.ietf.org/doc/html/rfc7518#section-3.2
func NewSourcedHMACVerifier(source *jwk.Source, preset HMACPreset) *SourcedHMACVerifier {
	newVerifier := func(key []byte) jwt.RecipientPlugin { return NewHMACVerifier(key, preset) }

	return &SourcedHMACVerifier{newSourcedVerifier(source, consumeHMAC(preset.Alg), newVerifier)}
}
