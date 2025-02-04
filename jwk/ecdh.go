package jwk

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"

	"github.com/a-novel-kit/jwt/jwa"
	"github.com/a-novel-kit/jwt/jwk/serializers"
)

// GenerateECDH generates a new ECDH key pair.
//
// You can either retrieve the secret key directly (using res.Key()), or marshal the result into a JSON Web Key,
// using json.Marshal.
func GenerateECDH() (*Key[*ecdh.PrivateKey], *Key[*ecdh.PublicKey], error) {
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("(GenerateECDH) generate private key: %w", err)
	}

	publicKey := privateKey.PublicKey()

	privatePayload, err := serializers.EncodeECDH(privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("(GenerateECDH) encode private key: %w", err)
	}
	publicPayload, err := serializers.EncodeECDH(publicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("(GenerateECDH) encode public key: %w", err)
	}

	kid := uuid.NewString()

	privateHeader := jwa.JWKCommon{
		KTY:    jwa.KTYOKP,
		Use:    jwa.UseEnc,
		KeyOps: []jwa.KeyOp{jwa.KeyOpDeriveKey},
		Alg:    jwa.ECDHES,
		KID:    kid,
	}
	publicHeader := jwa.JWKCommon{
		KTY:    jwa.KTYOKP,
		Use:    jwa.UseEnc,
		KeyOps: []jwa.KeyOp{jwa.KeyOpDeriveKey},
		Alg:    jwa.ECDHES,
		KID:    kid,
	}

	privateSerialized, err := json.Marshal(privatePayload)
	if err != nil {
		return nil, nil, fmt.Errorf("(GenerateECDH) serialize private key: %w", err)
	}
	publicSerialized, err := json.Marshal(publicPayload)
	if err != nil {
		return nil, nil, fmt.Errorf("(GenerateECDH) serialize public key: %w", err)
	}

	privateJSONKey := &jwa.JWK{
		JWKCommon: privateHeader,
		Payload:   privateSerialized,
	}
	publicJSONKey := &jwa.JWK{
		JWKCommon: publicHeader,
		Payload:   publicSerialized,
	}

	return &Key[*ecdh.PrivateKey]{privateJSONKey, privateKey}, &Key[*ecdh.PublicKey]{publicJSONKey, publicKey}, nil
}

// ConsumeECDH consumes a JSON Web Key and returns the secret key for ECDH encryption algorithms.
//
// If the JSON Web Key does not represent the ECDH key, ErrJWKMismatch is returned.
//
// If the key represents a public key only, the private key will be nil.
func ConsumeECDH(source *jwa.JWK) (*Key[*ecdh.PrivateKey], *Key[*ecdh.PublicKey], error) {
	if !source.MatchPreset(jwa.JWKCommon{
		KTY:    jwa.KTYOKP,
		Use:    jwa.UseEnc,
		KeyOps: []jwa.KeyOp{jwa.KeyOpDeriveKey},
		Alg:    jwa.ECDHES,
	}) {
		return nil, nil, fmt.Errorf("(ConsumeECDH) %w", ErrJWKMismatch)
	}

	var ecdhPayload serializers.ECDHPayload
	if err := json.Unmarshal(source.Payload, &ecdhPayload); err != nil {
		return nil, nil, fmt.Errorf("(ConsumeECDH) unmarshal payload: %w", err)
	}

	decodedPrivate, decodedPublic, err := serializers.DecodeECDH(&ecdhPayload)
	if err != nil {
		return nil, nil, fmt.Errorf("(ConsumeECDH) decode payload: %w", err)
	}

	var (
		privateKey *Key[*ecdh.PrivateKey]
		publicKey  *Key[*ecdh.PublicKey]
	)

	if decodedPrivate != nil {
		privateKey = NewKey[*ecdh.PrivateKey](source, decodedPrivate)
	}
	if decodedPublic != nil {
		publicKey = NewKey[*ecdh.PublicKey](source, decodedPublic)
	}

	return privateKey, publicKey, nil
}

func NewECDHPublicSource(config SourceConfig) *Source[*ecdh.PublicKey] {
	parser := func(ctx context.Context, jwk *jwa.JWK) (*Key[*ecdh.PublicKey], error) {
		privateKey, publicKey, err := ConsumeECDH(jwk)
		if privateKey != nil {
			return nil, fmt.Errorf("(NewECDHPublicSource) %w: source is providing private keys", ErrJWKMismatch)
		}

		return publicKey, err
	}

	return NewGenericSource[*ecdh.PublicKey](config, parser)
}

func NewECDHPrivateSource(config SourceConfig) *Source[*ecdh.PrivateKey] {
	parser := func(ctx context.Context, jwk *jwa.JWK) (*Key[*ecdh.PrivateKey], error) {
		privateKey, _, err := ConsumeECDH(jwk)
		if privateKey == nil {
			return nil, fmt.Errorf("(NewECDHPrivateSource) %w: source is providing public keys", ErrJWKMismatch)
		}

		return privateKey, err
	}

	return NewGenericSource[*ecdh.PrivateKey](config, parser)
}
