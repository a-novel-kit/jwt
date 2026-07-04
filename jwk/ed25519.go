package jwk

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"

	"github.com/a-novel-kit/jwt/v2/jwa"
	"github.com/a-novel-kit/jwt/v2/jwk/serializers"
)

// GenerateED25519 generates a new Ed25519 key pair.
//
// Retrieve a raw key with res.Key(), or marshal either result into a JSON Web Key with json.Marshal.
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
		KeyOps: jwa.KeyOps{jwa.KeyOpSign},
		Alg:    jwa.EdDSA,
		KID:    kid,
	}
	publicHeader := jwa.JWKCommon{
		KTY:    jwa.KTYOKP,
		Use:    jwa.UseSig,
		KeyOps: jwa.KeyOps{jwa.KeyOpVerify},
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

// ConsumeED25519 parses a JSON Web Key into an Ed25519 signature key pair. When the key holds only
// a public key, the returned private key is nil.
//
// It returns ErrJWKMismatch when the key does not represent an Ed25519 key.
func ConsumeED25519(source *jwa.JWK) (*Key[ed25519.PrivateKey], *Key[ed25519.PublicKey], error) {
	matchPrivate := source.MatchPreset(jwa.JWKCommon{
		KTY:    jwa.KTYOKP,
		Use:    jwa.UseSig,
		KeyOps: jwa.KeyOps{jwa.KeyOpSign},
		Alg:    jwa.EdDSA,
	})
	matchPublic := source.MatchPreset(jwa.JWKCommon{
		KTY:    jwa.KTYOKP,
		Use:    jwa.UseSig,
		KeyOps: jwa.KeyOps{jwa.KeyOpVerify},
		Alg:    jwa.EdDSA,
	})

	if !matchPrivate && !matchPublic {
		return nil, nil, fmt.Errorf("(ConsumeED25519) %w", ErrJWKMismatch)
	}

	var ed2519Payload serializers.EDPayload

	err := json.Unmarshal(source.Payload, &ed2519Payload)
	if err != nil {
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
