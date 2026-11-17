package jwt

import (
	"fmt"
	"strings"
)

// ErrUnsupportedTokenFormat is returned when a recipient cannot parse a token, such as one with a
// segment that is not base64url. It reports a malformed token, and matches [ErrTokenRejected].
var ErrUnsupportedTokenFormat = fmt.Errorf("%w: unsupported token format", ErrTokenRejected)

// HeaderDecoder extracts the encoded header, the first segment, from any compact token regardless
// of its shape.
type HeaderDecoder struct{}

// Decode returns the encoded header of source. It returns [ErrUnsupportedTokenFormat] when source
// holds a single segment.
func (decoder *HeaderDecoder) Decode(source string) (string, error) {
	header, _, found := strings.Cut(source, ".")
	if !found {
		// The token is an untrusted bearer credential, so the error names the shape only.
		return "", fmt.Errorf("%w: expected at least 2 segments", ErrUnsupportedTokenFormat)
	}

	return header, nil
}

// A RawToken is an unsecured token: a header and payload with no signature or encryption.
type RawToken struct {
	// Header is the base64url-encoded JOSE header.
	Header string
	// Payload is the base64url-encoded claims set.
	Payload string
}

// String returns the compact "header.payload" serialization.
func (token RawToken) String() string {
	return token.Header + "." + token.Payload
}

// RawTokenDecoder decodes an unsecured token into its header and payload segments.
type RawTokenDecoder struct{}

// Decode splits source into its header and payload. It returns [ErrUnsupportedTokenFormat] unless
// source holds exactly two segments.
func (decoder *RawTokenDecoder) Decode(source string) (*RawToken, error) {
	// Limit is segments+1, so an over-segmented token still trips the length check below while the cap
	// bounds the allocation a dot-heavy input can force.
	parts := strings.SplitN(source, ".", 3)
	if len(parts) != 2 {
		return nil, fmt.Errorf("%w: expected 2 segments", ErrUnsupportedTokenFormat)
	}

	return &RawToken{
		Header:  parts[0],
		Payload: parts[1],
	}, nil
}

// A SignedToken is the three-segment JWS compact form.
type SignedToken struct {
	// Header is the base64url-encoded protected header.
	Header string
	// Payload is the base64url-encoded claims set.
	Payload string
	// Signature is the base64url-encoded signature over "header.payload".
	Signature string
}

// String returns the compact "header.payload.signature" serialization.
func (token SignedToken) String() string {
	return token.Header + "." + token.Payload + "." + token.Signature
}

// SignedTokenDecoder decodes a JWS compact token into its three segments.
type SignedTokenDecoder struct{}

// Decode splits source into its three segments. It returns [ErrUnsupportedTokenFormat] unless source
// holds exactly three.
func (decoder *SignedTokenDecoder) Decode(source string) (*SignedToken, error) {
	parts := strings.SplitN(source, ".", 4)
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: expected 3 segments", ErrUnsupportedTokenFormat)
	}

	return &SignedToken{
		Header:    parts[0],
		Payload:   parts[1],
		Signature: parts[2],
	}, nil
}

// An EncryptedToken is the five-segment JWE compact form. Every segment is base64url-encoded.
type EncryptedToken struct {
	// Header is the protected header, which the integrity check also covers.
	Header string
	// EncKey is the encrypted content encryption key. It is empty when no key travels with the token,
	// as with direct encryption or ECDH-ES.
	EncKey string
	// IV is the initialization vector of the content encryption.
	IV string
	// CipherText is the encrypted claims set.
	CipherText string
	// Tag is the authentication tag of the content encryption.
	Tag string
}

// String returns the compact "header.key.iv.ciphertext.tag" serialization.
func (token EncryptedToken) String() string {
	return token.Header + "." + token.EncKey + "." + token.IV + "." + token.CipherText + "." + token.Tag
}

// EncryptedTokenDecoder decodes a JWE compact token into its five segments.
type EncryptedTokenDecoder struct{}

// Decode splits source into its five segments. It returns [ErrUnsupportedTokenFormat] unless source
// holds exactly five.
func (decoder *EncryptedTokenDecoder) Decode(source string) (*EncryptedToken, error) {
	parts := strings.SplitN(source, ".", 6)
	if len(parts) != 5 {
		return nil, fmt.Errorf("%w: expected 5 segments", ErrUnsupportedTokenFormat)
	}

	return &EncryptedToken{
		Header:     parts[0],
		EncKey:     parts[1],
		IV:         parts[2],
		CipherText: parts[3],
		Tag:        parts[4],
	}, nil
}
