package jwk

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"

	"github.com/a-novel-kit/jwt/v2/jwa"
	"github.com/a-novel-kit/jwt/v2/jwk/generators"
	"github.com/a-novel-kit/jwt/v2/jwk/serializers"
)

// An HMACPreset describes how to generate or match an HMAC JSON Web Key: the algorithm it is bound
// to and its key size in bytes.
type HMACPreset struct {
	Alg     jwa.Alg
	KeySize int
}

var (
	HS256 = HMACPreset{
		Alg: jwa.HS256,
		// If the key is more than 64 bytes long, it is hashed (using SHA-256) to derive a 32-byte key.
		// https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.hmacsha256.-ctor?view=net-9.0
		KeySize: 64,
	}
	HS384 = HMACPreset{
		Alg: jwa.HS384,
		// If the key is more than 128 bytes long, it is hashed (using SHA-384) to derive a 48-byte key.
		// https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.hmacsha384.-ctor?view=net-9.0
		KeySize: 128,
	}
	HS512 = HMACPreset{
		Alg: jwa.HS512,
		// If the key is more than 128 bytes long, it is hashed (using SHA-512) to derive a 64-byte key.
		// https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.hmacsha512.-ctor?view=net-9.0
		KeySize: 128,
	}
)

// GenerateHMAC generates a new secret key for HMAC signature algorithms.
//
// Retrieve the raw key with res.Key(), or marshal the result into a JSON Web Key with json.Marshal.
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

// NewHMACSource returns a key source that parses the HMAC keys matching preset.
func NewHMACSource(config SourceConfig, preset HMACPreset) *Source[[]byte] {
	parser := func(_ context.Context, jwk *jwa.JWK) (*Key[[]byte], error) {
		return ConsumeHMAC(jwk, preset)
	}

	return NewGenericSource[[]byte](config, parser)
}
