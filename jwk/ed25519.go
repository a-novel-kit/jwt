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
// Call Key on either result for the native key, or marshal it into a JSON Web Key with json.Marshal.
func GenerateED25519() (*Key[ed25519.PrivateKey], *Key[ed25519.PublicKey], error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("(GenerateED25519) generate key pair: %w", err)
	}

	privatePayload := serializers.EncodeED(privateKey)
	publicPayload := serializers.EncodeED(publicKey)

	privateSerialized, err := json.Marshal(privatePayload)
	if err != nil {
		return nil, nil, fmt.Errorf("(GenerateED25519) serialize private key: %w", err)
	}

	publicSerialized, err := json.Marshal(publicPayload)
	if err != nil {
		return nil, nil, fmt.Errorf("(GenerateED25519) serialize public key: %w", err)
	}

	kid := uuid.NewString()
	privateHeader := signatureHeader(jwa.KTYOKP, jwa.Ed25519, jwa.KeyOpSign)
	publicHeader := signatureHeader(jwa.KTYOKP, jwa.Ed25519, jwa.KeyOpVerify)
	privateHeader.KID, publicHeader.KID = kid, kid

	return NewKey(&jwa.JWK{JWKCommon: privateHeader, Payload: privateSerialized}, privateKey),
		NewKey(&jwa.JWK{JWKCommon: publicHeader, Payload: publicSerialized}, publicKey),
		nil
}

// ConsumeED25519 parses a JSON Web Key into an Ed25519 signature key pair. When the key holds only
// a public key, the returned private key is nil. A key labeled with the deprecated "EdDSA" algorithm
// is accepted as well.
//
// It returns ErrJWKMismatch when the key does not represent an Ed25519 key.
func ConsumeED25519(source *jwa.JWK) (*Key[ed25519.PrivateKey], *Key[ed25519.PublicKey], error) {
	common := source.JWKCommon
	if common.Alg == jwa.EdDSA { //nolint:staticcheck // RFC 9864 keeps EdDSA keys valid as Ed25519 ones.
		common.Alg = jwa.Ed25519
	}

	matchPrivate := common.MatchPreset(signatureHeader(jwa.KTYOKP, jwa.Ed25519, jwa.KeyOpSign))
	matchPublic := common.MatchPreset(signatureHeader(jwa.KTYOKP, jwa.Ed25519, jwa.KeyOpVerify))

	if !matchPrivate && !matchPublic {
		return nil, nil, fmt.Errorf("(ConsumeED25519) %w", ErrJWKMismatch)
	}

	var edPayload serializers.EDPayload

	err := json.Unmarshal(source.Payload, &edPayload)
	if err != nil {
		return nil, nil, fmt.Errorf("(ConsumeED25519) unmarshal payload: %w", err)
	}

	decodedPrivate, decodedPublic, err := serializers.DecodeED(&edPayload)
	if err != nil {
		return nil, nil, fmt.Errorf("(ConsumeED25519) decode payload: %w", err)
	}

	var privateKey *Key[ed25519.PrivateKey]

	if decodedPrivate != nil {
		privateKey = NewKey(source, decodedPrivate)
	}

	return privateKey, NewKey(source, decodedPublic), nil
}
