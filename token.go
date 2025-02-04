package jwt

import (
	"errors"
	"fmt"
	"strings"
)

var ErrUnsupportedTokenFormat = errors.New("unsupported token format")

type TokenDecoder[R any] interface {
	Decode(source string) (R, error)
}

type HeaderDecoder struct{}

func (decoder *HeaderDecoder) Decode(source string) (string, error) {
	parts := strings.Split(source, ".")
	if len(parts) < 2 {
		return "", fmt.Errorf("(HeaderDecoder.Decode) %w (%s)", ErrUnsupportedTokenFormat, source)
	}

	return parts[0], nil
}

type RawToken struct {
	Header  string
	Payload string
}

func (token RawToken) String() string {
	return fmt.Sprintf("%s.%s", token.Header, token.Payload)
}

func (token RawToken) Bytes() []byte {
	return []byte(token.String())
}

type RawTokenDecoder struct{}

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

type SignedToken struct {
	Header    string
	Payload   string
	Signature string
}

func (token SignedToken) String() string {
	return fmt.Sprintf("%s.%s.%s", token.Header, token.Payload, token.Signature)
}

func (token SignedToken) Bytes() []byte {
	return []byte(token.String())
}

type SignedTokenDecoder struct{}

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

type EncryptedToken struct {
	Header     string
	EncKey     string
	IV         string
	CipherText string
	Tag        string
}

func (token EncryptedToken) String() string {
	return fmt.Sprintf("%s.%s.%s.%s.%s", token.Header, token.EncKey, token.IV, token.CipherText, token.Tag)
}

func (token EncryptedToken) Bytes() []byte {
	return []byte(token.String())
}

type EncryptedTokenDecoder struct{}

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

func DecodeToken[R any](source string, decoder TokenDecoder[R]) (R, error) {
	return decoder.Decode(source)
}
