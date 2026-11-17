package jwk

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"

	"github.com/a-novel-kit/jwt/v2/jwa"
	"github.com/a-novel-kit/jwt/v2/jwk/serializers"
)

// An ECDHPreset describes how to generate or match a key-agreement JSON Web Key. Keys on X25519
// serialize as "OKP" keys, keys on the NIST curves as "EC" keys.
type ECDHPreset struct {
	// Alg is the key management algorithm the key is bound to.
	Alg jwa.Alg
	// Curve is the curve the key lives on.
	Curve ecdh.Curve
}

var (
	// ECDHESX25519 generates or matches an X25519 key for ECDH-ES.
	ECDHESX25519 = ECDHPreset{
		Alg:   jwa.ECDHES,
		Curve: ecdh.X25519(),
	}
	// ECDHESP256 generates or matches a P-256 key for ECDH-ES, the curve RFC 7518 recommends.
	ECDHESP256 = ECDHPreset{
		Alg:   jwa.ECDHES,
		Curve: ecdh.P256(),
	}
	// ECDHESP384 generates or matches a P-384 key for ECDH-ES.
	ECDHESP384 = ECDHPreset{
		Alg:   jwa.ECDHES,
		Curve: ecdh.P384(),
	}
	// ECDHESP521 generates or matches a P-521 key for ECDH-ES.
	ECDHESP521 = ECDHPreset{
		Alg:   jwa.ECDHES,
		Curve: ecdh.P521(),
	}
)

// GenerateECDHKey generates a new key-agreement key pair on the preset's curve.
//
// Call Key on either result for the native key, or marshal it into a JSON Web Key with json.Marshal.
//
// Pass one of the ECDH presets, such as [ECDHESP256].
func GenerateECDHKey(preset ECDHPreset) (*Key[*ecdh.PrivateKey], *Key[*ecdh.PublicKey], error) {
	privateKey, err := preset.Curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate private key: %w", err)
	}

	publicKey := privateKey.PublicKey()

	privatePayload, err := serializers.EncodeECDH(privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("encode private key: %w", err)
	}

	publicPayload, err := serializers.EncodeECDH(publicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("encode public key: %w", err)
	}

	// Each half gets its own header, so the two keys share no slice.
	private, public, err := newKeyPair(
		privateKey, privatePayload, ecdhHeader(preset),
		publicKey, publicPayload, ecdhHeader(preset),
	)
	if err != nil {
		return nil, nil, err
	}

	return private, public, nil
}

// ConsumeECDHKey parses a JSON Web Key into a key-agreement key pair. When the key holds only a
// public key, the returned private key is nil.
//
// It returns ErrJWKMismatch when the key does not match the preset, including a key on another
// curve. Pass the same preset used to generate the key; see [GenerateECDHKey].
func ConsumeECDHKey(source *jwa.JWK, preset ECDHPreset) (*Key[*ecdh.PrivateKey], *Key[*ecdh.PublicKey], error) {
	privateKey, publicKey, err := consumeKeyPair(source, ecdhHeader(preset), ecdhHeader(preset), serializers.DecodeECDH)
	if err != nil {
		return nil, nil, err
	}

	// The curve lives in the payload, where the preset match cannot see it.
	if curve := publicKey.Key().Curve(); curve != preset.Curve {
		return nil, nil, fmt.Errorf(
			"%w: key is on %v, preset requires %v", ErrJWKMismatch, curve, preset.Curve,
		)
	}

	return privateKey, publicKey, nil
}

// ecdhHeader returns the common parameters of a key-agreement key for preset. Both halves of the
// pair share them, since each derives the agreed key. GenerateECDHKey stamps them with a key ID, and
// ConsumeECDHKey requires them.
func ecdhHeader(preset ECDHPreset) jwa.JWKCommon {
	return jwa.JWKCommon{
		KTY:    serializers.ECDHKeyType(preset.Curve),
		Use:    jwa.UseEnc,
		KeyOps: jwa.KeyOps{jwa.KeyOpDeriveKey},
		Alg:    preset.Alg,
	}
}
