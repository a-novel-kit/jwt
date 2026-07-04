package jwk

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"

	"github.com/a-novel-kit/jwt/jwa"
	"github.com/a-novel-kit/jwt/jwk/serializers"
)

// An ECDSAPreset describes how to generate or match an ECDSA JSON Web Key: the algorithm it is
// bound to and the elliptic curve its keys live on.
type ECDSAPreset struct {
	Alg   jwa.Alg
	Curve elliptic.Curve
}

// Signature algorithms.
var (
	ES256 = ECDSAPreset{
		Alg:   jwa.ES256,
		Curve: elliptic.P256(),
	}
	ES384 = ECDSAPreset{
		Alg:   jwa.ES384,
		Curve: elliptic.P384(),
	}
	ES512 = ECDSAPreset{
		Alg:   jwa.ES512,
		Curve: elliptic.P521(),
	}
)

// GenerateECDSA generates a new ECDSA key pair.
//
// Retrieve a raw key with res.Key(), or marshal either result into a JSON Web Key with json.Marshal.
//
// Pass one of the ECDSA presets, such as [ES256].
func GenerateECDSA(preset ECDSAPreset) (*Key[*ecdsa.PrivateKey], *Key[*ecdsa.PublicKey], error) {
	privateKey, err := ecdsa.GenerateKey(preset.Curve, rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("(GenerateECDSA) generate private key: %w", err)
	}

	publicKey := &privateKey.PublicKey

	privatePayload, err := serializers.EncodeEC(privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("(GenerateECDSA) encode private key: %w", err)
	}

	publicPayload, err := serializers.EncodeEC(publicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("(GenerateECDSA) encode public key: %w", err)
	}

	kid := uuid.NewString()

	privateHeader := jwa.JWKCommon{
		KTY:    jwa.KTYEC,
		Use:    jwa.UseSig,
		KeyOps: jwa.KeyOps{jwa.KeyOpSign},
		Alg:    preset.Alg,
		KID:    kid,
	}
	publicHeader := jwa.JWKCommon{
		KTY:    jwa.KTYEC,
		Use:    jwa.UseSig,
		KeyOps: jwa.KeyOps{jwa.KeyOpVerify},
		Alg:    preset.Alg,
		KID:    kid,
	}

	privateSerialized, err := json.Marshal(privatePayload)
	if err != nil {
		return nil, nil, fmt.Errorf("(GenerateECDSA) serialize private key: %w", err)
	}

	publicSerialized, err := json.Marshal(publicPayload)
	if err != nil {
		return nil, nil, fmt.Errorf("(GenerateECDSA) serialize public key: %w", err)
	}

	privateJSONKey := &jwa.JWK{
		JWKCommon: privateHeader,
		Payload:   privateSerialized,
	}
	publicJSONKey := &jwa.JWK{
		JWKCommon: publicHeader,
		Payload:   publicSerialized,
	}

	return &Key[*ecdsa.PrivateKey]{privateJSONKey, privateKey}, &Key[*ecdsa.PublicKey]{publicJSONKey, publicKey}, nil
}

// ConsumeECDSA parses a JSON Web Key into an ECDSA signature key pair. When the key holds only a
// public key, the returned private key is nil.
//
// It returns ErrJWKMismatch when the key does not match the preset. Pass the same preset used to
// generate the key; see [GenerateECDSA] for the available presets.
func ConsumeECDSA(source *jwa.JWK, preset ECDSAPreset) (*Key[*ecdsa.PrivateKey], *Key[*ecdsa.PublicKey], error) {
	matchPrivate := source.MatchPreset(jwa.JWKCommon{
		KTY:    jwa.KTYEC,
		Use:    jwa.UseSig,
		KeyOps: jwa.KeyOps{jwa.KeyOpSign},
		Alg:    preset.Alg,
	})
	matchPublic := source.MatchPreset(jwa.JWKCommon{
		KTY:    jwa.KTYEC,
		Use:    jwa.UseSig,
		KeyOps: jwa.KeyOps{jwa.KeyOpVerify},
		Alg:    preset.Alg,
	})

	if !matchPrivate && !matchPublic {
		return nil, nil, fmt.Errorf("(ConsumeECDSA) %w", ErrJWKMismatch)
	}

	var ecPayload serializers.ECPayload

	err := json.Unmarshal(source.Payload, &ecPayload)
	if err != nil {
		return nil, nil, fmt.Errorf("(ConsumeECDSA) unmarshal payload: %w", err)
	}

	decodedPrivate, decodedPublic, err := serializers.DecodeEC(&ecPayload)
	if err != nil {
		return nil, nil, fmt.Errorf("(ConsumeECDSA) decode payload: %w", err)
	}

	var (
		privateKey *Key[*ecdsa.PrivateKey]
		publicKey  *Key[*ecdsa.PublicKey]
	)

	if decodedPrivate != nil {
		privateKey = NewKey[*ecdsa.PrivateKey](source, decodedPrivate)
	}

	if decodedPublic != nil {
		publicKey = NewKey[*ecdsa.PublicKey](source, decodedPublic)
	}

	return privateKey, publicKey, nil
}

// NewECDSAPublicSource returns a key source that yields ECDSA public keys and rejects any source
// that exposes private key material.
func NewECDSAPublicSource(config SourceConfig, preset ECDSAPreset) *Source[*ecdsa.PublicKey] {
	parser := func(_ context.Context, jwk *jwa.JWK) (*Key[*ecdsa.PublicKey], error) {
		privateKey, publicKey, err := ConsumeECDSA(jwk, preset)
		if privateKey != nil {
			return nil, fmt.Errorf("(NewECDSAPublicSource) %w: source is providing private keys", ErrJWKMismatch)
		}

		return publicKey, err
	}

	return NewGenericSource[*ecdsa.PublicKey](config, parser)
}

// NewECDSAPrivateSource returns a key source that yields ECDSA private keys.
func NewECDSAPrivateSource(config SourceConfig, preset ECDSAPreset) *Source[*ecdsa.PrivateKey] {
	parser := func(_ context.Context, jwk *jwa.JWK) (*Key[*ecdsa.PrivateKey], error) {
		privateKey, _, err := ConsumeECDSA(jwk, preset)
		if privateKey == nil {
			return nil, fmt.Errorf("(NewECDSAPrivateSource) %w: source is providing public keys", ErrJWKMismatch)
		}

		return privateKey, err
	}

	return NewGenericSource[*ecdsa.PrivateKey](config, parser)
}
