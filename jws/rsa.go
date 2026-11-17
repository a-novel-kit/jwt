package jws

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"

	"github.com/a-novel-kit/jwt/v2"
	"github.com/a-novel-kit/jwt/v2/jwa"
	"github.com/a-novel-kit/jwt/v2/jwk"
)

// An RSAPreset describes an RSA signing scheme. Pass one of the exported presets to the RSA
// constructors. The RS* presets use RSASSA-PKCS1-v1_5 and the PS* presets RSASSA-PSS, both on the
// same RSA keys.
type RSAPreset struct {
	// Hash digests the signing input.
	Hash crypto.Hash
	// Alg is the signature algorithm, which also selects the scheme.
	Alg jwa.Alg
}

var (
	// RS256 is RSASSA-PKCS1-v1_5 using SHA-256.
	RS256 = RSAPreset{Hash: crypto.SHA256, Alg: jwa.RS256}
	// RS384 is RSASSA-PKCS1-v1_5 using SHA-384.
	RS384 = RSAPreset{Hash: crypto.SHA384, Alg: jwa.RS384}
	// RS512 is RSASSA-PKCS1-v1_5 using SHA-512.
	RS512 = RSAPreset{Hash: crypto.SHA512, Alg: jwa.RS512}
	// PS256 is RSASSA-PSS using SHA-256 and MGF1 with SHA-256.
	PS256 = RSAPreset{Hash: crypto.SHA256, Alg: jwa.PS256}
	// PS384 is RSASSA-PSS using SHA-384 and MGF1 with SHA-384.
	PS384 = RSAPreset{Hash: crypto.SHA384, Alg: jwa.PS384}
	// PS512 is RSASSA-PSS using SHA-512 and MGF1 with SHA-512.
	PS512 = RSAPreset{Hash: crypto.SHA512, Alg: jwa.PS512}
)

// algIsPSS reports whether alg selects RSASSA-PSS. It returns [ErrUnsupportedAlgorithm] for anything
// that is not an RS* or PS* algorithm, so a hand-assembled preset fails before it signs.
func algIsPSS(alg jwa.Alg) (bool, error) {
	switch alg {
	case jwa.RS256, jwa.RS384, jwa.RS512:
		return false, nil
	case jwa.PS256, jwa.PS384, jwa.PS512:
		return true, nil
	default:
		return false, fmt.Errorf("%w: %s", ErrUnsupportedAlgorithm, alg)
	}
}

// An RSASigner signs tokens with RSA (RSASSA-PKCS1-v1_5 or RSASSA-PSS, per the preset) as a
// [jwt.ProducerPlugin]. Build one with [NewRSASigner].
type RSASigner struct {
	secretKey *rsa.PrivateKey

	alg  jwa.Alg
	hash crypto.Hash
}

// NewRSASigner returns a [jwt.ProducerPlugin] that signs tokens with RSA, using the hash carried by
// the preset (one of [RS256], [RS384], [RS512], [PS256], [PS384], [PS512]). The preset's algorithm
// selects PKCS1v15 (RS*) or PSS (PS*). The key must be at least 2048 bits.
//
// See RFC 7518, sections 3.3 and 3.5: https://datatracker.ietf.org/doc/html/rfc7518#section-3.3
func NewRSASigner(secretKey *rsa.PrivateKey, preset RSAPreset) *RSASigner {
	return &RSASigner{
		secretKey: secretKey,
		alg:       preset.Alg,
		hash:      preset.Hash,
	}
}

func (signer *RSASigner) Header(_ context.Context, header *jwa.JWH) (*jwa.JWH, error) {
	return signHeader(header, signer.alg, checkRSAPrivateKey(signer.secretKey))
}

func (signer *RSASigner) Transform(_ context.Context, _ *jwa.JWH, rawToken string) (string, error) {
	return signToken(rawToken, checkRSAPrivateKey(signer.secretKey), signer.sign)
}

// sign produces the RSA signature over signingInput using the scheme its algorithm denotes. PSS uses
// a salt length equal to the hash, the value RFC 7518 §3.5 mandates for the PS* algorithms.
func (signer *RSASigner) sign(signingInput []byte) ([]byte, error) {
	pss, err := algIsPSS(signer.alg)
	if err != nil {
		return nil, err
	}

	hasher := signer.hash.New()
	hasher.Write(signingInput)

	if pss {
		return rsa.SignPSS(rand.Reader, signer.secretKey, signer.hash, hasher.Sum(nil), &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
		})
	}

	return rsa.SignPKCS1v15(rand.Reader, signer.secretKey, signer.hash, hasher.Sum(nil))
}

// An RSAVerifier verifies RSA-signed tokens (RSASSA-PKCS1-v1_5 or RSASSA-PSS, per the preset) as a
// [jwt.RecipientPlugin]. Build one with [NewRSAVerifier]. It returns [ErrInvalidSignature] when the
// signature does not match.
type RSAVerifier struct {
	publicKey *rsa.PublicKey

	alg  jwa.Alg
	hash crypto.Hash
}

// NewRSAVerifier returns a [jwt.RecipientPlugin] that verifies RSA-signed tokens, using the hash
// carried by the preset (one of [RS256], [RS384], [RS512], [PS256], [PS384], [PS512]). The preset's
// algorithm selects PKCS1v15 (RS*) or PSS (PS*). It accepts only tokens whose alg matches the
// preset's, so an RS* verifier rejects a PS* token.
//
// See RFC 7518, sections 3.3 and 3.5: https://datatracker.ietf.org/doc/html/rfc7518#section-3.3
func NewRSAVerifier(publicKey *rsa.PublicKey, preset RSAPreset) *RSAVerifier {
	return &RSAVerifier{
		publicKey: publicKey,
		alg:       preset.Alg,
		hash:      preset.Hash,
	}
}

func (verifier *RSAVerifier) Transform(_ context.Context, header *jwa.JWH, rawToken string) ([]byte, error) {
	return verifyToken(header, verifier.alg, checkRSAPublicKey(verifier.publicKey), rawToken, verifier.verify)
}

// verify checks the RSA signature over signingInput using the scheme its algorithm denotes.
//
// RFC 7518 §3.5 sets the PSS salt to the hash size, which the signer uses. The verifier deliberately
// accepts any salt length (PSSSaltLengthAuto), so it interoperates with signers that pad differently.
// The salt length does not weaken PSS.
func (verifier *RSAVerifier) verify(signingInput, signature []byte) error {
	pss, err := algIsPSS(verifier.alg)
	if err != nil {
		return err
	}

	hasher := verifier.hash.New()
	hasher.Write(signingInput)

	if pss {
		err = rsa.VerifyPSS(verifier.publicKey, verifier.hash, hasher.Sum(nil), signature, &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthAuto,
		})
	} else {
		err = rsa.VerifyPKCS1v15(verifier.publicKey, verifier.hash, hasher.Sum(nil), signature)
	}

	if errors.Is(err, rsa.ErrVerification) {
		return errors.Join(ErrInvalidSignature, err)
	}

	return err
}

// minRSAKeyBits is the smallest RSA modulus the RS* and PS* algorithms accept, per RFC 7518 §3.3
// and §3.5 ("A key of size 2048 bits or larger MUST be used"). Enforced at both sign and verify.
const minRSAKeyBits = 2048

// checkRSAPublicKey fails closed unless key is a usable RSA public key: non-nil, with a positive
// modulus of at least minRSAKeyBits. BitLen reads the absolute value, so the sign is checked
// separately. A negative modulus clears the bit-length floor.
func checkRSAPublicKey(key *rsa.PublicKey) error {
	if key == nil || key.N == nil || key.N.Sign() <= 0 {
		return fmt.Errorf("%w: RSA key has no valid modulus", jwt.ErrInvalidSecretKey)
	}

	if key.N.BitLen() < minRSAKeyBits {
		return fmt.Errorf(
			"%w: RSA key is %d bits, need at least %d",
			jwt.ErrInvalidSecretKey, key.N.BitLen(), minRSAKeyBits,
		)
	}

	return nil
}

// checkRSAPrivateKey applies checkRSAPublicKey to a private key's public half, rejecting a nil key
// first so the dereference is safe.
func checkRSAPrivateKey(key *rsa.PrivateKey) error {
	if key == nil {
		return fmt.Errorf("%w: nil RSA key", jwt.ErrInvalidSecretKey)
	}

	return checkRSAPublicKey(&key.PublicKey)
}

// consumeRSA binds [jwk.ConsumeRSA] to a signature key for alg, as GenerateRSA labels one.
func consumeRSA(alg jwa.Alg) keyPair[*rsa.PrivateKey, *rsa.PublicKey] {
	preset := jwk.RSAPreset{
		Alg:           alg,
		Use:           jwa.UseSig,
		PrivateKeyOps: jwa.KeyOps{jwa.KeyOpSign},
		PublicKeyOps:  jwa.KeyOps{jwa.KeyOpVerify},
	}

	return func(key *jwa.JWK) (*jwk.Key[*rsa.PrivateKey], *jwk.Key[*rsa.PublicKey], error) {
		return jwk.ConsumeRSA(key, preset)
	}
}

// A SourcedRSASigner signs like an [RSASigner] but resolves its key from a [jwk.Source] at each
// call, so the plugin follows key rotation. Build one with [NewSourcedRSASigner].
type SourcedRSASigner struct {
	*sourcedSigner[*rsa.PrivateKey]
}

// NewSourcedRSASigner returns a [jwt.ProducerPlugin] that signs tokens with RSA, drawing the key from
// the source for the header's KID. The preset (one of [RS256], [RS384], [RS512], [PS256], [PS384],
// [PS512]) selects the hash and scheme, and the key must be at least 2048 bits.
//
// See RFC 7518, sections 3.3 and 3.5: https://datatracker.ietf.org/doc/html/rfc7518#section-3.3
func NewSourcedRSASigner(source *jwk.Source, preset RSAPreset) *SourcedRSASigner {
	newSigner := func(key *rsa.PrivateKey) jwt.ProducerPlugin { return NewRSASigner(key, preset) }

	return &SourcedRSASigner{newSourcedSigner(source, privateHalf(consumeRSA(preset.Alg)), newSigner)}
}

// A SourcedRSAVerifier verifies like an [RSAVerifier] but resolves candidate keys from a
// [jwk.Source] at each call. When the token names a KID, it tries only that key. Otherwise it tries
// every key in the source. Build one with [NewSourcedRSAVerifier].
type SourcedRSAVerifier struct {
	*sourcedVerifier[*rsa.PublicKey]
}

// NewSourcedRSAVerifier returns a [jwt.RecipientPlugin] that verifies RSA-signed tokens against keys
// drawn from the source. The preset (one of [RS256], [RS384], [RS512], [PS256], [PS384], [PS512])
// selects the hash and scheme.
//
// See RFC 7518, sections 3.3 and 3.5: https://datatracker.ietf.org/doc/html/rfc7518#section-3.3
func NewSourcedRSAVerifier(source *jwk.Source, preset RSAPreset) *SourcedRSAVerifier {
	newVerifier := func(key *rsa.PublicKey) jwt.RecipientPlugin { return NewRSAVerifier(key, preset) }

	return &SourcedRSAVerifier{newSourcedVerifier(source, publicHalf(consumeRSA(preset.Alg)), newVerifier)}
}
