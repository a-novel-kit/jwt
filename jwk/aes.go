package jwk

import (
	"encoding/json"
	"fmt"

	"github.com/google/uuid"

	"github.com/a-novel-kit/jwt/v2/jwa"
	"github.com/a-novel-kit/jwt/v2/jwk/generators"
	"github.com/a-novel-kit/jwt/v2/jwk/serializers"
)

// An AESPreset describes how to generate or match an AES JSON Web Key.
type AESPreset struct {
	// Alg is the algorithm the key is bound to: a content encryption "enc" value, or a key-wrapping
	// "alg" value.
	Alg jwa.Alg
	// KeyOps are the operations the key permits.
	KeyOps jwa.KeyOps
	// KeySize is the length of a generated key, in bytes.
	KeySize int
}

var (
	// A128CBC generates or matches the 32-byte content encryption key of A128CBC-HS256.
	A128CBC = AESPreset{
		Alg: jwa.Alg(jwa.A128CBC),
		KeyOps: jwa.KeyOps{
			jwa.KeyOpEncrypt,
			jwa.KeyOpDecrypt,
		},
		KeySize: 32,
	}
	// A192CBC generates or matches the 48-byte content encryption key of A192CBC-HS384.
	A192CBC = AESPreset{
		Alg: jwa.Alg(jwa.A192CBC),
		KeyOps: jwa.KeyOps{
			jwa.KeyOpEncrypt,
			jwa.KeyOpDecrypt,
		},
		KeySize: 48,
	}
	// A256CBC generates or matches the 64-byte content encryption key of A256CBC-HS512.
	A256CBC = AESPreset{
		Alg: jwa.Alg(jwa.A256CBC),
		KeyOps: jwa.KeyOps{
			jwa.KeyOpEncrypt,
			jwa.KeyOpDecrypt,
		},
		KeySize: 64,
	}

	// A128GCM generates or matches the 16-byte content encryption key of A128GCM.
	A128GCM = AESPreset{
		Alg: jwa.Alg(jwa.A128GCM),
		KeyOps: jwa.KeyOps{
			jwa.KeyOpEncrypt,
			jwa.KeyOpDecrypt,
		},
		KeySize: 16,
	}
	// A192GCM generates or matches the 24-byte content encryption key of A192GCM.
	A192GCM = AESPreset{
		Alg: jwa.Alg(jwa.A192GCM),
		KeyOps: jwa.KeyOps{
			jwa.KeyOpEncrypt,
			jwa.KeyOpDecrypt,
		},
		KeySize: 24,
	}
	// A256GCM generates or matches the 32-byte content encryption key of A256GCM.
	A256GCM = AESPreset{
		Alg: jwa.Alg(jwa.A256GCM),
		KeyOps: jwa.KeyOps{
			jwa.KeyOpEncrypt,
			jwa.KeyOpDecrypt,
		},
		KeySize: 32,
	}
)

var (
	// A128KW generates or matches the 16-byte key-wrapping key of A128KW.
	A128KW = AESPreset{
		Alg: jwa.A128KW,
		KeyOps: jwa.KeyOps{
			jwa.KeyOpWrapKey,
			jwa.KeyOpUnwrapKey,
		},
		KeySize: 16,
	}
	// A192KW generates or matches the 24-byte key-wrapping key of A192KW.
	A192KW = AESPreset{
		Alg: jwa.A192KW,
		KeyOps: jwa.KeyOps{
			jwa.KeyOpWrapKey,
			jwa.KeyOpUnwrapKey,
		},
		KeySize: 24,
	}
	// A256KW generates or matches the 32-byte key-wrapping key of A256KW.
	A256KW = AESPreset{
		Alg: jwa.A256KW,
		KeyOps: jwa.KeyOps{
			jwa.KeyOpWrapKey,
			jwa.KeyOpUnwrapKey,
		},
		KeySize: 32,
	}

	// A128GCMKW generates or matches the 16-byte key-wrapping key of A128GCMKW.
	A128GCMKW = AESPreset{
		Alg: jwa.A128GCMKW,
		KeyOps: jwa.KeyOps{
			jwa.KeyOpWrapKey,
			jwa.KeyOpUnwrapKey,
		},
		KeySize: 16,
	}
	// A192GCMKW generates or matches the 24-byte key-wrapping key of A192GCMKW.
	A192GCMKW = AESPreset{
		Alg: jwa.A192GCMKW,
		KeyOps: jwa.KeyOps{
			jwa.KeyOpWrapKey,
			jwa.KeyOpUnwrapKey,
		},
		KeySize: 24,
	}
	// A256GCMKW generates or matches the 32-byte key-wrapping key of A256GCMKW.
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
// Call Key on the result for the native key, or marshal it into a JSON Web Key with json.Marshal.
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
