package serializers

import (
	"encoding/base64"
	"fmt"
)

// OctPayload wraps a symmetric key in a JWKCommon format.
type OctPayload struct {
	// K (CEK Value) Parameter.
	//
	// https://datatracker.ietf.org/doc/html/rfc7518#section-6.4.1
	//
	// The "k" (key value) parameter contains the value of the symmetric (or
	// other single-valued) key. It is represented as the base64url
	// encoding of the octet sequence containing the key value.
	K string `json:"k"`
}

// DecodeOct takes the representation of a OctPayload and computes the key it contains.
func DecodeOct(src *OctPayload) ([]byte, error) {
	key, err := base64.RawURLEncoding.DecodeString(src.K)
	if err != nil {
		return nil, fmt.Errorf("decode key: %w", err)
	}

	return key, nil
}

// EncodeOct takes a key and create a OctPayload representation of it.
func EncodeOct(key []byte) *OctPayload {
	return &OctPayload{
		K: base64.RawURLEncoding.EncodeToString(key),
	}
}
