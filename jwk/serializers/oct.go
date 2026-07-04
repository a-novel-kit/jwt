package serializers

import (
	"encoding/base64"
	"fmt"
)

// An OctPayload wraps a symmetric key in a JWKCommon format.
type OctPayload struct {
	// K is the base64url-encoded symmetric key value.
	//
	// https://datatracker.ietf.org/doc/html/rfc7518#section-6.4.1
	K string `json:"k"`
}

// DecodeOct returns the raw key bytes carried by an OctPayload.
func DecodeOct(src *OctPayload) ([]byte, error) {
	key, err := base64.RawURLEncoding.DecodeString(src.K)
	if err != nil {
		return nil, fmt.Errorf("decode key: %w", err)
	}

	return key, nil
}

// EncodeOct wraps a raw symmetric key as an OctPayload.
func EncodeOct(key []byte) *OctPayload {
	return &OctPayload{
		K: base64.RawURLEncoding.EncodeToString(key),
	}
}
