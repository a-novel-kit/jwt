package jwa

import (
	"encoding/json"

	"github.com/samber/lo"

	"github.com/a-novel-kit/jwt/v2/jwa/internal"
)

// JWKCommon holds the parameters common to every JSON Web Key, independent of
// key type. Type-specific parameters (the actual key material) live alongside
// them in the payload; see JWK.
//
// https://datatracker.ietf.org/doc/html/rfc7517#section-4
type JWKCommon struct {
	J509

	// KTY is the key type, the cryptographic algorithm family of the key. It is
	// the only required member of a JWK.
	// https://datatracker.ietf.org/doc/html/rfc7518#section-6.1
	KTY KTY `json:"kty"`
	// Use marks the key as intended for signing or for encryption. It is
	// mutually informative with KeyOps and should stay consistent with it.
	// https://datatracker.ietf.org/doc/html/rfc7517#section-4.2
	Use Use `json:"use,omitempty"`
	// KeyOps lists the operations the key may perform. It offers finer control
	// than Use; the two should not disagree when both are set.
	// https://datatracker.ietf.org/doc/html/rfc7517#section-4.3
	KeyOps KeyOps `json:"key_ops,omitempty"`
	// Alg names the algorithm the key is intended to be used with.
	// https://datatracker.ietf.org/doc/html/rfc7517#section-4.4
	Alg Alg `json:"alg,omitempty"`
	// KID is a hint identifying which key was used, letting an originator signal
	// a key change. When keys are matched by identifier, this is the value
	// compared.
	// https://datatracker.ietf.org/doc/html/rfc7517#section-4.5
	KID string `json:"kid,omitempty"`
}

// MatchPreset reports whether the key satisfies the given preset: it has the
// same key type, use, and algorithm, and its operations include every one the
// preset requires.
func (jwk JWKCommon) MatchPreset(other JWKCommon) bool {
	for _, keyOp := range other.KeyOps {
		if !lo.Contains(jwk.KeyOps, keyOp) {
			return false
		}
	}

	return jwk.KTY == other.KTY &&
		jwk.Use == other.Use &&
		jwk.Alg == other.Alg
}

// JWK is a full JSON Web Key: the common parameters plus the type-specific key
// material carried in the payload. Marshaling merges the two into one JSON
// object.
type JWK struct {
	JWKCommon

	Payload json.RawMessage
}

func (key JWK) MarshalJSON() ([]byte, error) {
	return internal.MarshalPartial(key.JWKCommon, key.Payload)
}

func (key *JWK) UnmarshalJSON(src []byte) error {
	var err error

	key.JWKCommon, key.Payload, err = internal.UnmarshalPartial[JWKCommon](src)

	return err
}
