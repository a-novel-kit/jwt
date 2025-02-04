package jwk

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"

	"github.com/a-novel-kit/jwt/jwa"
	"github.com/a-novel-kit/jwt/jwk/serializers"
)

// GenerateED25519 generates a new ED25519 key pair.
//
// You can either retrieve the secret key directly (using res.Key()), or marshal the result into a JSON Web Key,
// using json.Marshal.
func GenerateED25519() (*Key[ed25519.PrivateKey], *Key[ed25519.PublicKey], error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("(GenerateED25519) generate key pair: %w", err)
	}

	privatePayload := serializers.EncodeED(privateKey)
	publicPayload := serializers.EncodeED(publicKey)

	kid := uuid.NewString()

	privateHeader := jwa.JWKCommon{
		KTY:    jwa.KTYOKP,
		Use:    jwa.UseSig,
		KeyOps: []jwa.KeyOp{jwa.KeyOpSign},
		Alg:    jwa.EdDSA,
		KID:    kid,
	}
	publicHeader := jwa.JWKCommon{
		KTY:    jwa.KTYOKP,
		Use:    jwa.UseSig,
		KeyOps: []jwa.KeyOp{jwa.KeyOpVerify},
		Alg:    jwa.EdDSA,
		KID:    kid,
	}

	privateSerialized, err := json.Marshal(privatePayload)
	if err != nil {
		return nil, nil, fmt.Errorf("(GenerateED25519) serialize private key: %w", err)
	}
	publicSerialized, err := json.Marshal(publicPayload)
	if err != nil {
		return nil, nil, fmt.Errorf("(GenerateED25519) serialize public key: %w", err)
	}

	privateJSONKey := &jwa.JWK{
		JWKCommon: privateHeader,
		Payload:   privateSerialized,
	}
	publicJSONKey := &jwa.JWK{
		JWKCommon: publicHeader,
		Payload:   publicSerialized,
	}

	return NewKey[ed25519.PrivateKey](privateJSONKey, privateKey),
		NewKey[ed25519.PublicKey](publicJSONKey, publicKey),
		nil
}

// ConsumeED25519 consumes a JSON Web Key and returns the secret key for ED25519 signature algorithms.
//
// If the JSON Web Key does not represent the ED25519 key, ErrJWKMismatch is returned.
//
// If the key represents a public key only, the private key will be nil.
func ConsumeED25519(source *jwa.JWK) (*Key[ed25519.PrivateKey], *Key[ed25519.PublicKey], error) {
	matchPrivate := source.MatchPreset(jwa.JWKCommon{
		KTY:    jwa.KTYOKP,
		Use:    jwa.UseSig,
		KeyOps: []jwa.KeyOp{jwa.KeyOpSign},
		Alg:    jwa.EdDSA,
	})
	matchPublic := source.MatchPreset(jwa.JWKCommon{
		KTY:    jwa.KTYOKP,
		Use:    jwa.UseSig,
		KeyOps: []jwa.KeyOp{jwa.KeyOpVerify},
		Alg:    jwa.EdDSA,
	})
	if !matchPrivate && !matchPublic {
		return nil, nil, fmt.Errorf("(ConsumeED25519) %w", ErrJWKMismatch)
	}

	var ed2519Payload serializers.EDPayload
	if err := json.Unmarshal(source.Payload, &ed2519Payload); err != nil {
		return nil, nil, fmt.Errorf("(ConsumeED25519) unmarshal payload: %w", err)
	}

	decodedPrivate, decodedPublic, err := serializers.DecodeED(&ed2519Payload)
	if err != nil {
		return nil, nil, fmt.Errorf("(ConsumeED25519) decode payload: %w", err)
	}

	var (
		privateKey *Key[ed25519.PrivateKey]
		publicKey  *Key[ed25519.PublicKey]
	)

	if decodedPrivate != nil {
		privateKey = &Key[ed25519.PrivateKey]{source, decodedPrivate}
	}
	if decodedPublic != nil {
		publicKey = &Key[ed25519.PublicKey]{source, decodedPublic}
	}

	return privateKey, publicKey, nil
}

func NewED25519PublicSource(config SourceConfig) *Source[ed25519.PublicKey] {
	parser := func(ctx context.Context, jwk *jwa.JWK) (*Key[ed25519.PublicKey], error) {
		privateKey, publicKey, err := ConsumeED25519(jwk)
		if privateKey != nil {
			return nil, fmt.Errorf("(NewED25519PublicSource) %w: source is providing private keys", ErrJWKMismatch)
		}

		return publicKey, err
	}

	return NewGenericSource[ed25519.PublicKey](config, parser)
}

func NewED25519PrivateSource(config SourceConfig) *Source[ed25519.PrivateKey] {
	parser := func(ctx context.Context, jwk *jwa.JWK) (*Key[ed25519.PrivateKey], error) {
		privateKey, _, err := ConsumeED25519(jwk)
		if privateKey == nil {
			return nil, fmt.Errorf("(NewED25519PrivateSource) %w: source is providing public keys", ErrJWKMismatch)
		}

		return privateKey, err
	}

	return NewGenericSource[ed25519.PrivateKey](config, parser)
}
