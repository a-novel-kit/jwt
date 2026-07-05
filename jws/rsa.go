package jws

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/a-novel-kit/jwt/v2"
	"github.com/a-novel-kit/jwt/v2/jwa"
	"github.com/a-novel-kit/jwt/v2/jwk"
)

// An RSAScheme selects which RSA signature scheme a preset drives. Both operate on the same RSA keys;
// only the padding and the algorithm identifier differ.
type RSAScheme uint8

const (
	// RSASchemePKCS1v15 is RSASSA-PKCS1-v1_5 (the RS* algorithms).
	RSASchemePKCS1v15 RSAScheme = iota
	// RSASchemePSS is RSASSA-PSS (the PS* algorithms), using the same hash for the digest and MGF1.
	RSASchemePSS
)

// An RSAPreset bundles the hash, algorithm identifier, and scheme for one RSA signing scheme. Pass
// one of the exported presets to the RSA constructors rather than assembling the fields by hand: the
// RS* presets use RSASSA-PKCS1-v1_5, the PS* presets use RSASSA-PSS. Both run on the same RSA keys.
type RSAPreset struct {
	Hash   crypto.Hash
	Alg    jwa.Alg
	Scheme RSAScheme
}

var (
	// RS256 is RSASSA-PKCS1-v1_5 using SHA-256.
	RS256 = RSAPreset{
		Hash:   crypto.SHA256,
		Alg:    jwa.RS256,
		Scheme: RSASchemePKCS1v15,
	}
	// RS384 is RSASSA-PKCS1-v1_5 using SHA-384.
	RS384 = RSAPreset{
		Hash:   crypto.SHA384,
		Alg:    jwa.RS384,
		Scheme: RSASchemePKCS1v15,
	}
	// RS512 is RSASSA-PKCS1-v1_5 using SHA-512.
	RS512 = RSAPreset{
		Hash:   crypto.SHA512,
		Alg:    jwa.RS512,
		Scheme: RSASchemePKCS1v15,
	}
	// PS256 is RSASSA-PSS using SHA-256 and MGF1 with SHA-256.
	PS256 = RSAPreset{
		Hash:   crypto.SHA256,
		Alg:    jwa.PS256,
		Scheme: RSASchemePSS,
	}
	// PS384 is RSASSA-PSS using SHA-384 and MGF1 with SHA-384.
	PS384 = RSAPreset{
		Hash:   crypto.SHA384,
		Alg:    jwa.PS384,
		Scheme: RSASchemePSS,
	}
	// PS512 is RSASSA-PSS using SHA-512 and MGF1 with SHA-512.
	PS512 = RSAPreset{
		Hash:   crypto.SHA512,
		Alg:    jwa.PS512,
		Scheme: RSASchemePSS,
	}
)

// An RSASigner signs tokens with RSA (RSASSA-PKCS1-v1_5 or RSASSA-PSS, per the preset) as a
// [jwt.ProducerPlugin]. Build one with [NewRSASigner].
type RSASigner struct {
	secretKey *rsa.PrivateKey

	alg    jwa.Alg
	hash   crypto.Hash
	scheme RSAScheme
}

// NewRSASigner returns a [jwt.ProducerPlugin] that signs tokens with RSA, using the hash and scheme
// carried by the preset (one of [RS256], [RS384], [RS512], [PS256], [PS384], [PS512]). The key must
// be at least 2048 bits.
//
// See RFC 7518, sections 3.3 and 3.5: https://datatracker.ietf.org/doc/html/rfc7518#section-3.3
func NewRSASigner(secretKey *rsa.PrivateKey, preset RSAPreset) *RSASigner {
	return &RSASigner{
		secretKey: secretKey,
		alg:       preset.Alg,
		hash:      preset.Hash,
		scheme:    preset.Scheme,
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

	signature, err := signer.sign(hasher.Sum(nil))
	if err != nil {
		return "", fmt.Errorf("(RSASigner.Transform) %w", err)
	}

	return jwt.SignedToken{
		Header:    token.Header,
		Payload:   token.Payload,
		Signature: base64.RawURLEncoding.EncodeToString(signature),
	}.String(), nil
}

// sign produces the RSA signature over digest using the signer's scheme. PSS uses a salt length
// equal to the hash, the value RFC 7518 §3.5 mandates for the PS* algorithms.
func (signer *RSASigner) sign(digest []byte) ([]byte, error) {
	if signer.scheme == RSASchemePSS {
		return rsa.SignPSS(rand.Reader, signer.secretKey, signer.hash, digest, &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
		})
	}

	return rsa.SignPKCS1v15(rand.Reader, signer.secretKey, signer.hash, digest)
}

// An RSAVerifier verifies RSA-signed tokens (RSASSA-PKCS1-v1_5 or RSASSA-PSS, per the preset) as a
// [jwt.RecipientPlugin]. Build one with [NewRSAVerifier]. It returns [ErrInvalidSignature] when the
// signature does not match.
type RSAVerifier struct {
	publicKey *rsa.PublicKey

	alg    jwa.Alg
	hash   crypto.Hash
	scheme RSAScheme
}

// NewRSAVerifier returns a [jwt.RecipientPlugin] that verifies RSA-signed tokens, using the hash and
// scheme carried by the preset (one of [RS256], [RS384], [RS512], [PS256], [PS384], [PS512]). It
// accepts only tokens whose alg matches the preset's, so an RS* verifier rejects a PS* token.
//
// See RFC 7518, sections 3.3 and 3.5: https://datatracker.ietf.org/doc/html/rfc7518#section-3.3
func NewRSAVerifier(publicKey *rsa.PublicKey, preset RSAPreset) *RSAVerifier {
	return &RSAVerifier{
		publicKey: publicKey,
		alg:       preset.Alg,
		hash:      preset.Hash,
		scheme:    preset.Scheme,
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

	err = verifier.verify(hasher.Sum(nil), sigBytes)
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

// verify checks the RSA signature over digest using the verifier's scheme. PSS accepts any salt
// length (PSSSaltLengthAuto), so it interoperates with signers that pad differently.
func (verifier *RSAVerifier) verify(digest, sig []byte) error {
	if verifier.scheme == RSASchemePSS {
		return rsa.VerifyPSS(verifier.publicKey, verifier.hash, digest, sig, &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthAuto,
		})
	}

	return rsa.VerifyPKCS1v15(verifier.publicKey, verifier.hash, digest, sig)
}

// sourcedRSAPublic decodes a raw JSON Web Key into an RSA public key for verification, matching only
// signature keys bound to alg and skipping any that carry private material (signing keys, which a
// verifier does not use). It backs the sourced RSA verifiers for every RS*/PS* alg.
func sourcedRSAPublic(alg jwa.Alg) keyDecoder[*rsa.PublicKey] {
	preset := jwk.RSAPreset{
		Alg:           alg,
		Use:           jwa.UseSig,
		PrivateKeyOps: jwa.KeyOps{jwa.KeyOpSign},
		PublicKeyOps:  jwa.KeyOps{jwa.KeyOpVerify},
	}

	return func(key *jwa.JWK) (*rsa.PublicKey, error) {
		privateKey, publicKey, err := jwk.ConsumeRSA(key, preset)
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

// sourcedRSAPrivate decodes a raw JSON Web Key into an RSA private key for signing, matching only
// signature keys bound to alg.
func sourcedRSAPrivate(alg jwa.Alg) keyDecoder[*rsa.PrivateKey] {
	preset := jwk.RSAPreset{
		Alg:           alg,
		Use:           jwa.UseSig,
		PrivateKeyOps: jwa.KeyOps{jwa.KeyOpSign},
		PublicKeyOps:  jwa.KeyOps{jwa.KeyOpVerify},
	}

	return func(key *jwa.JWK) (*rsa.PrivateKey, error) {
		privateKey, _, err := jwk.ConsumeRSA(key, preset)
		if err != nil {
			return nil, err
		}

		if privateKey == nil {
			return nil, fmt.Errorf("%w", jwk.ErrJWKMismatch)
		}

		return privateKey.Key(), nil
	}
}

// A SourcedRSASigner signs like an [RSASigner] but resolves its key from a [jwk.Source] at each
// call, so the plugin follows key rotation instead of pinning one key. Build one with
// [NewSourcedRSASigner].
type SourcedRSASigner struct {
	source *jwk.Source
	preset RSAPreset
}

// NewSourcedRSASigner returns a [jwt.ProducerPlugin] that signs tokens with RSA, drawing the key from
// the source for the header's KID. The preset (one of [RS256], [RS384], [RS512], [PS256], [PS384],
// [PS512]) selects the hash and scheme, and the key must be at least 2048 bits.
//
// See RFC 7518, sections 3.3 and 3.5: https://datatracker.ietf.org/doc/html/rfc7518#section-3.3
func NewSourcedRSASigner(source *jwk.Source, preset RSAPreset) *SourcedRSASigner {
	return &SourcedRSASigner{
		source: source,
		preset: preset,
	}
}

func (signer *SourcedRSASigner) Header(ctx context.Context, header *jwa.JWH) (*jwa.JWH, error) {
	key, kid, err := signFromSource(ctx, signer.source, header.KID, sourcedRSAPrivate(signer.preset.Alg))
	if err != nil {
		return nil, fmt.Errorf("(SourcedRSASigner.Header) %w", err)
	}

	// Stamp the resolved key's ID into the header so recipients can select it for verification.
	if header.KID == "" {
		header.KID = kid
	}

	return NewRSASigner(key, signer.preset).Header(ctx, header)
}

func (signer *SourcedRSASigner) Transform(ctx context.Context, header *jwa.JWH, rawToken string) (string, error) {
	key, _, err := signFromSource(ctx, signer.source, header.KID, sourcedRSAPrivate(signer.preset.Alg))
	if err != nil {
		return "", fmt.Errorf("(SourcedRSASigner.Transform) %w", err)
	}

	return NewRSASigner(key, signer.preset).Transform(ctx, header, rawToken)
}

// A SourcedRSAVerifier verifies like an [RSAVerifier] but resolves candidate keys from a
// [jwk.Source] at each call. When the token names a KID it tries only that key; otherwise it tries
// every key in the source. Build one with [NewSourcedRSAVerifier].
type SourcedRSAVerifier struct {
	source *jwk.Source
	preset RSAPreset
}

// NewSourcedRSAVerifier returns a [jwt.RecipientPlugin] that verifies RSA-signed tokens against keys
// drawn from the source. The preset (one of [RS256], [RS384], [RS512], [PS256], [PS384], [PS512])
// selects the hash and scheme.
//
// See RFC 7518, sections 3.3 and 3.5: https://datatracker.ietf.org/doc/html/rfc7518#section-3.3
func NewSourcedRSAVerifier(source *jwk.Source, preset RSAPreset) *SourcedRSAVerifier {
	return &SourcedRSAVerifier{
		source: source,
		preset: preset,
	}
}

func (verifier *SourcedRSAVerifier) Transform(
	ctx context.Context, header *jwa.JWH, rawToken string,
) ([]byte, error) {
	return verifyFromSource(ctx, verifier.source, header, rawToken, sourcedRSAPublic(verifier.preset.Alg),
		func(key *rsa.PublicKey) jwt.RecipientPlugin {
			return NewRSAVerifier(key, verifier.preset)
		})
}
