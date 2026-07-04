package jwt

import (
	"errors"
	"fmt"
	"strings"
)

// ErrUnsupportedTokenFormat is returned when a token does not split into the number of segments a
// decoder expects.
var ErrUnsupportedTokenFormat = errors.New("unsupported token format")

// A TokenDecoder splits a compact serialized token into its typed segments. Each JOSE token shape
// — unsecured, signed, encrypted — has its own decoder producing its own segment type.
type TokenDecoder[R any] interface {
	Decode(source string) (R, error)
}

// HeaderDecoder extracts the encoded header, the first segment, from any compact token regardless
// of its shape.
type HeaderDecoder struct{}

// Decode implements [TokenDecoder].
func (decoder *HeaderDecoder) Decode(source string) (string, error) {
	parts := strings.Split(source, ".")
	if len(parts) < 2 {
		return "", fmt.Errorf("(HeaderDecoder.Decode) %w (%s)", ErrUnsupportedTokenFormat, source)
	}

	return parts[0], nil
}

// A RawToken is an unsecured token: a header and payload with no signature or encryption.
type RawToken struct {
	Header  string
	Payload string
}

// String returns the compact "header.payload" serialization.
func (token RawToken) String() string {
	return fmt.Sprintf("%s.%s", token.Header, token.Payload)
}

// Bytes returns String as a byte slice.
func (token RawToken) Bytes() []byte {
	return []byte(token.String())
}

// RawTokenDecoder decodes an unsecured token into its header and payload segments.
type RawTokenDecoder struct{}

// Decode implements [TokenDecoder].
func (decoder *RawTokenDecoder) Decode(source string) (*RawToken, error) {
	parts := strings.Split(source, ".")
	if len(parts) != 2 {
		return nil, fmt.Errorf("(RawTokenDecoder.Decode) %w (%s)", ErrUnsupportedTokenFormat, source)
	}

	return &RawToken{
		Header:  parts[0],
		Payload: parts[1],
	}, nil
}

// A SignedToken is the three-segment JWS compact form: header, payload, and signature.
type SignedToken struct {
	Header    string
	Payload   string
	Signature string
}

// String returns the compact "header.payload.signature" serialization.
func (token SignedToken) String() string {
	return fmt.Sprintf("%s.%s.%s", token.Header, token.Payload, token.Signature)
}

// Bytes returns String as a byte slice.
func (token SignedToken) Bytes() []byte {
	return []byte(token.String())
}

// SignedTokenDecoder decodes a JWS compact token into its three segments.
type SignedTokenDecoder struct{}

// Decode implements [TokenDecoder].
func (decoder *SignedTokenDecoder) Decode(source string) (*SignedToken, error) {
	parts := strings.Split(source, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("(SignedTokenDecoder.Decode) %w (%s)", ErrUnsupportedTokenFormat, source)
	}

	return &SignedToken{
		Header:    parts[0],
		Payload:   parts[1],
		Signature: parts[2],
	}, nil
}

// An EncryptedToken is the five-segment JWE compact form: header, encrypted key, initialization
// vector, ciphertext, and authentication tag.
type EncryptedToken struct {
	Header     string
	EncKey     string
	IV         string
	CipherText string
	Tag        string
}

// String returns the compact "header.key.iv.ciphertext.tag" serialization.
func (token EncryptedToken) String() string {
	return fmt.Sprintf("%s.%s.%s.%s.%s", token.Header, token.EncKey, token.IV, token.CipherText, token.Tag)
}

// Bytes returns String as a byte slice.
func (token EncryptedToken) Bytes() []byte {
	return []byte(token.String())
}

// EncryptedTokenDecoder decodes a JWE compact token into its five segments.
type EncryptedTokenDecoder struct{}

// Decode implements [TokenDecoder].
func (decoder *EncryptedTokenDecoder) Decode(source string) (*EncryptedToken, error) {
	parts := strings.Split(source, ".")
	if len(parts) != 5 {
		return nil, fmt.Errorf("(EncryptedTokenDecoder.Decode) %w (%s)", ErrUnsupportedTokenFormat, source)
	}

	return &EncryptedToken{
		Header:     parts[0],
		EncKey:     parts[1],
		IV:         parts[2],
		CipherText: parts[3],
		Tag:        parts[4],
	}, nil
}

// DecodeToken runs decoder over source and returns the typed segments. It lets a caller decode a
// token by passing the matching decoder rather than naming its segment type.
func DecodeToken[R any](source string, decoder TokenDecoder[R]) (R, error) {
	return decoder.Decode(source)
}
