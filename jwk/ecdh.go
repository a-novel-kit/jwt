package jwk

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"

	"github.com/a-novel-kit/jwt/v2/jwa"
	"github.com/a-novel-kit/jwt/v2/jwk/serializers"
)

// An ECDHPreset describes how to generate or match a key-agreement JSON Web Key: the algorithm it is
// bound to and the curve its keys live on. Keys on X25519 serialize as "OKP" keys, keys on the NIST
// curves as "EC" keys.
type ECDHPreset struct {
	Alg   jwa.Alg
	Curve ecdh.Curve
}

// ECDH-ES key agreement, one preset per curve. RFC 7518 recommends P-256.
var (
	ECDHESX25519 = ECDHPreset{
		Alg:   jwa.ECDHES,
		Curve: ecdh.X25519(),
	}
	ECDHESP256 = ECDHPreset{
		Alg:   jwa.ECDHES,
		Curve: ecdh.P256(),
	}
	ECDHESP384 = ECDHPreset{
		Alg:   jwa.ECDHES,
		Curve: ecdh.P384(),
	}
	ECDHESP521 = ECDHPreset{
		Alg:   jwa.ECDHES,
		Curve: ecdh.P521(),
	}
)

// GenerateECDHKey generates a new key-agreement key pair on the preset's curve.
//
// Retrieve a raw key with res.Key(), or marshal either result into a JSON Web Key with json.Marshal.
//
// Pass one of the ECDH presets, such as [ECDHESP256].
func GenerateECDHKey(preset ECDHPreset) (*Key[*ecdh.PrivateKey], *Key[*ecdh.PublicKey], error) {
	privateKey, err := preset.Curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("(GenerateECDHKey) generate private key: %w", err)
	}

	publicKey := privateKey.PublicKey()

	privatePayload, err := serializers.EncodeECDH(privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("(GenerateECDHKey) encode private key: %w", err)
	}

	publicPayload, err := serializers.EncodeECDH(publicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("(GenerateECDHKey) encode public key: %w", err)
	}

	privateSerialized, err := json.Marshal(privatePayload)
	if err != nil {
		return nil, nil, fmt.Errorf("(GenerateECDHKey) serialize private key: %w", err)
	}

	publicSerialized, err := json.Marshal(publicPayload)
	if err != nil {
		return nil, nil, fmt.Errorf("(GenerateECDHKey) serialize public key: %w", err)
	}

	// Each half gets its own header, so the two keys share no slice.
	kid := uuid.NewString()
	privateHeader, publicHeader := ecdhHeader(preset), ecdhHeader(preset)
	privateHeader.KID, publicHeader.KID = kid, kid

	return NewKey(&jwa.JWK{JWKCommon: privateHeader, Payload: privateSerialized}, privateKey),
		NewKey(&jwa.JWK{JWKCommon: publicHeader, Payload: publicSerialized}, publicKey),
		nil
}

// ConsumeECDHKey parses a JSON Web Key into a key-agreement key pair. When the key holds only a
// public key, the returned private key is nil.
//
// It returns ErrJWKMismatch when the key does not match the preset, including a key on another
// curve. Pass the same preset used to generate the key; see [GenerateECDHKey].
func ConsumeECDHKey(source *jwa.JWK, preset ECDHPreset) (*Key[*ecdh.PrivateKey], *Key[*ecdh.PublicKey], error) {
	if !source.MatchPreset(ecdhHeader(preset)) {
		return nil, nil, fmt.Errorf("(ConsumeECDHKey) %w", ErrJWKMismatch)
	}

	var ecdhPayload serializers.ECDHPayload

	err := json.Unmarshal(source.Payload, &ecdhPayload)
	if err != nil {
		return nil, nil, fmt.Errorf("(ConsumeECDHKey) unmarshal payload: %w", err)
	}

	decodedPrivate, decodedPublic, err := serializers.DecodeECDH(&ecdhPayload)
	if err != nil {
		return nil, nil, fmt.Errorf("(ConsumeECDHKey) decode payload: %w", err)
	}

	// The curve lives in the payload, where MatchPreset cannot see it.
	if decodedPublic.Curve() != preset.Curve {
		return nil, nil, fmt.Errorf(
			"(ConsumeECDHKey) %w: key is on %v, preset requires %v", ErrJWKMismatch, decodedPublic.Curve(), preset.Curve,
		)
	}

	var privateKey *Key[*ecdh.PrivateKey]

	if decodedPrivate != nil {
		privateKey = NewKey(source, decodedPrivate)
	}

	return privateKey, NewKey(source, decodedPublic), nil
}

// ecdhHeader returns the common parameters of a key-agreement key for preset. Both halves of the
// pair share them: each derives the agreed key.
func ecdhHeader(preset ECDHPreset) jwa.JWKCommon {
	return jwa.JWKCommon{
		KTY:    serializers.ECDHKeyType(preset.Curve),
		Use:    jwa.UseEnc,
		KeyOps: jwa.KeyOps{jwa.KeyOpDeriveKey},
		Alg:    preset.Alg,
	}
}

// GenerateECDH generates a new ECDH-ES key pair on the X25519 curve.
//
// Deprecated: use [GenerateECDHKey] with [ECDHESX25519], or a preset for another curve.
func GenerateECDH() (*Key[*ecdh.PrivateKey], *Key[*ecdh.PublicKey], error) {
	return GenerateECDHKey(ECDHESX25519)
}

// ConsumeECDH parses a JSON Web Key into an X25519 ECDH-ES key pair.
//
// Deprecated: use [ConsumeECDHKey] with [ECDHESX25519], or a preset for another curve.
func ConsumeECDH(source *jwa.JWK) (*Key[*ecdh.PrivateKey], *Key[*ecdh.PublicKey], error) {
	return ConsumeECDHKey(source, ECDHESX25519)
}
