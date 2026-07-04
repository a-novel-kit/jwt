package jwe

import (
	"encoding/base64"
	"errors"
)

// ErrInvalidSecret is returned when the content encryption key resolved for a token
// has the wrong length for the chosen algorithm, or when an authentication tag fails
// to verify during decryption.
var ErrInvalidSecret = errors.New("invalid secret")

// ErrInvalidToken is returned when an encrypted token is structurally malformed — for example an
// initialization vector or padding of the wrong length.
var ErrInvalidToken = errors.New("invalid token")

// aad builds the additional data bound into the JWE integrity check — used as the AEAD AAD for
// AES-GCM and folded into the HMAC for AES-CBC-HMAC: the encoded protected header (RFC 7516 §5.1),
// plus the application additionalData appended as ".BASE64URL(additionalData)" when present (the JWE
// JSON-serialization AAD rule). Both encrypt and decrypt derive it from the transmitted header, so
// tampering with the header fails the integrity check.
func aad(encodedHeader string, additionalData []byte) []byte {
	out := []byte(encodedHeader)
	if len(additionalData) == 0 {
		return out
	}

	out = append(out, '.')

	return append(out, base64.RawURLEncoding.EncodeToString(additionalData)...)
}
