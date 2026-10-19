package jwk

import (
	"encoding/json"
	"fmt"

	"github.com/google/uuid"

	"github.com/a-novel-kit/jwt/v2/jwa"
	"github.com/a-novel-kit/jwt/v2/jwk/generators"
	"github.com/a-novel-kit/jwt/v2/jwk/serializers"
)

// An HMACPreset describes how to generate or match an HMAC JSON Web Key.
type HMACPreset struct {
	// Alg is the signature algorithm the key is bound to.
	Alg jwa.Alg
	// KeySize is the length of a generated key, in bytes. The presets use the block size of their
	// hash, the longest key HMAC takes without hashing it first (RFC 2104 §2).
	KeySize int
}

var (
	// HS256 generates or matches a 64-byte key for HMAC with SHA-256.
	HS256 = HMACPreset{
		Alg:     jwa.HS256,
		KeySize: 64,
	}
	// HS384 generates or matches a 128-byte key for HMAC with SHA-384.
	HS384 = HMACPreset{
		Alg:     jwa.HS384,
		KeySize: 128,
	}
	// HS512 generates or matches a 128-byte key for HMAC with SHA-512.
	HS512 = HMACPreset{
		Alg:     jwa.HS512,
		KeySize: 128,
	}
)

// GenerateHMAC generates a new secret key for HMAC signature algorithms.
//
// Call Key on the result for the native key, or marshal it into a JSON Web Key with json.Marshal.
//
// Pass one of the HMAC presets, such as [HS256].
func GenerateHMAC(preset HMACPreset) (*Key[[]byte], error) {
	key, err := generators.NewOct(preset.KeySize)
	if err != nil {
		return nil, fmt.Errorf("(GenerateHMAC) generate key: %w", err)
	}

	payload := serializers.EncodeOct(key)

	header := jwa.JWKCommon{
		KTY:    jwa.KTYOct,
		Use:    jwa.UseSig,
		KeyOps: jwa.KeyOps{jwa.KeyOpSign, jwa.KeyOpVerify},
		Alg:    preset.Alg,
		KID:    uuid.NewString(),
	}

	payloadSerialized, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("(GenerateHMAC) serialize payload: %w", err)
	}

	jsonKey := &jwa.JWK{
		JWKCommon: header,
		Payload:   payloadSerialized,
	}

	return &Key[[]byte]{jsonKey, key}, nil
}

// ConsumeHMAC parses a JSON Web Key into the secret key for an HMAC algorithm.
//
// It returns ErrJWKMismatch when the key does not match the preset. Pass the same preset used to
// generate the key; see [GenerateHMAC] for the available presets.
func ConsumeHMAC(source *jwa.JWK, preset HMACPreset) (*Key[[]byte], error) {
	if !source.MatchPreset(jwa.JWKCommon{
		KTY:    jwa.KTYOct,
		Use:    jwa.UseSig,
		KeyOps: jwa.KeyOps{jwa.KeyOpSign, jwa.KeyOpVerify},
		Alg:    preset.Alg,
	}) {
		return nil, fmt.Errorf("(ConsumeHMAC) %w", ErrJWKMismatch)
	}

	var octPayload serializers.OctPayload

	err := json.Unmarshal(source.Payload, &octPayload)
	if err != nil {
		return nil, fmt.Errorf("(ConsumeHMAC) unmarshal payload: %w", err)
	}

	decoded, err := serializers.DecodeOct(&octPayload)
	if err != nil {
		return nil, fmt.Errorf("(ConsumeHMAC) decode payload: %w", err)
	}

	return NewKey[[]byte](source, decoded), nil
}
