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

// An AESPreset describes how to generate or match an AES JSON Web Key: the algorithm it is bound
// to, the key operations it permits, and its key size in bytes.
type AESPreset struct {
	Alg     jwa.Alg
	KeyOps  jwa.KeyOps
	KeySize int
}

// Content-Encryption Keys (CEK).
var (
	A128CBC = AESPreset{
		Alg: jwa.Alg(jwa.A128CBC),
		KeyOps: jwa.KeyOps{
			jwa.KeyOpEncrypt,
			jwa.KeyOpDecrypt,
		},
		KeySize: 32,
	}
	A192CBC = AESPreset{
		Alg: jwa.Alg(jwa.A192CBC),
		KeyOps: jwa.KeyOps{
			jwa.KeyOpEncrypt,
			jwa.KeyOpDecrypt,
		},
		KeySize: 48,
	}
	A256CBC = AESPreset{
		Alg: jwa.Alg(jwa.A256CBC),
		KeyOps: jwa.KeyOps{
			jwa.KeyOpEncrypt,
			jwa.KeyOpDecrypt,
		},
		KeySize: 64,
	}

	A128GCM = AESPreset{
		Alg: jwa.Alg(jwa.A128GCM),
		KeyOps: jwa.KeyOps{
			jwa.KeyOpEncrypt,
			jwa.KeyOpDecrypt,
		},
		KeySize: 16,
	}
	A192GCM = AESPreset{
		Alg: jwa.Alg(jwa.A192GCM),
		KeyOps: jwa.KeyOps{
			jwa.KeyOpEncrypt,
			jwa.KeyOpDecrypt,
		},
		KeySize: 24,
	}
	A256GCM = AESPreset{
		Alg: jwa.Alg(jwa.A256GCM),
		KeyOps: jwa.KeyOps{
			jwa.KeyOpEncrypt,
			jwa.KeyOpDecrypt,
		},
		KeySize: 32,
	}
)

// Key-Encryption Keys (KEK).
var (
	A128KW = AESPreset{
		Alg: jwa.A128KW,
		KeyOps: jwa.KeyOps{
			jwa.KeyOpWrapKey,
			jwa.KeyOpUnwrapKey,
		},
		KeySize: 16,
	}
	A192KW = AESPreset{
		Alg: jwa.A192KW,
		KeyOps: jwa.KeyOps{
			jwa.KeyOpWrapKey,
			jwa.KeyOpUnwrapKey,
		},
		KeySize: 24,
	}
	A256KW = AESPreset{
		Alg: jwa.A256KW,
		KeyOps: jwa.KeyOps{
			jwa.KeyOpWrapKey,
			jwa.KeyOpUnwrapKey,
		},
		KeySize: 32,
	}

	A128GCMKW = AESPreset{
		Alg: jwa.A128GCMKW,
		KeyOps: jwa.KeyOps{
			jwa.KeyOpWrapKey,
			jwa.KeyOpUnwrapKey,
		},
		KeySize: 16,
	}
	A192GCMKW = AESPreset{
		Alg: jwa.A192GCMKW,
		KeyOps: jwa.KeyOps{
			jwa.KeyOpWrapKey,
			jwa.KeyOpUnwrapKey,
		},
		KeySize: 24,
	}
	A256GCMKW = AESPreset{
		Alg: jwa.A256GCMKW,
		KeyOps: jwa.KeyOps{
			jwa.KeyOpWrapKey,
			jwa.KeyOpUnwrapKey,
		},
		KeySize: 32,
	}
)

// GenerateAES generates a new secret key for AES encryption algorithms.
//
// Retrieve the raw key with res.Key(), or marshal the result into a JSON Web Key with json.Marshal.
//
// Pass one of the package's AES presets: the content-encryption presets, such as [A128GCM],
// produce a CEK, and the key-wrapping presets, such as [A128KW], produce a KEK.
func GenerateAES(preset AESPreset) (*Key[[]byte], error) {
	key, err := generators.NewOct(preset.KeySize)
	if err != nil {
		return nil, fmt.Errorf("(GenerateAES) generate key: %w", err)
	}

	payload := serializers.EncodeOct(key)

	header := jwa.JWKCommon{
		KTY:    jwa.KTYOct,
		Use:    jwa.UseEnc,
		KeyOps: preset.KeyOps,
		Alg:    preset.Alg,
		KID:    uuid.NewString(),
	}

	payloadSerialized, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("(GenerateAES) serialize payload: %w", err)
	}

	jsonKey := &jwa.JWK{
		JWKCommon: header,
		Payload:   payloadSerialized,
	}

	return &Key[[]byte]{jsonKey, key}, nil
}

// ConsumeAES parses a JSON Web Key into the secret key for an AES algorithm.
//
// It returns ErrJWKMismatch when the key does not match the preset. Pass the same preset used to
// generate the key; see [GenerateAES] for the available presets.
func ConsumeAES(source *jwa.JWK, preset AESPreset) (*Key[[]byte], error) {
	if !source.MatchPreset(jwa.JWKCommon{
		KTY:    jwa.KTYOct,
		Use:    jwa.UseEnc,
		KeyOps: preset.KeyOps,
		Alg:    preset.Alg,
	}) {
		return nil, fmt.Errorf("(ConsumeAES) %w", ErrJWKMismatch)
	}

	var octPayload serializers.OctPayload

	err := json.Unmarshal(source.Payload, &octPayload)
	if err != nil {
		return nil, fmt.Errorf("(ConsumeAES) unmarshal payload: %w", err)
	}

	decoded, err := serializers.DecodeOct(&octPayload)
	if err != nil {
		return nil, fmt.Errorf("(ConsumeAES) decode payload: %w", err)
	}

	return NewKey[[]byte](source, decoded), nil
}

// NewAESSource returns a key source that parses the AES keys matching preset.
func NewAESSource(config SourceConfig, preset AESPreset) *Source[[]byte] {
	parser := func(_ context.Context, jwk *jwa.JWK) (*Key[[]byte], error) {
		return ConsumeAES(jwk, preset)
	}

	return NewGenericSource[[]byte](config, parser)
}
