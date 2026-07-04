package jwek

import (
	"context"
	"fmt"

	"github.com/a-novel-kit/jwt/v2"
	"github.com/a-novel-kit/jwt/v2/jwa"
)

// DirectKeyManager implements jwe.CEKManager for direct encryption: the content
// encryption key is a shared secret used as-is, so nothing is wrapped into the
// token. See RFC 7518 section 4.5.
type DirectKeyManager struct {
	cek []byte
}

// NewDirectKeyManager creates a jwe.CEKManager that uses the given content
// encryption key directly, without wrapping it into the token.
//
// https://datatracker.ietf.org/doc/html/rfc7518#section-4.5
func NewDirectKeyManager(cek []byte) *DirectKeyManager {
	return &DirectKeyManager{
		cek: cek,
	}
}

func (manager *DirectKeyManager) SetHeader(_ context.Context, header *jwa.JWH) (*jwa.JWH, error) {
	if !header.Alg.Empty() {
		return nil, fmt.Errorf("(DirectKeyManager.SetHeader) %w: alg field already set", jwt.ErrConflictingHeader)
	}

	header.Alg = jwa.DIR

	return header, nil
}

func (manager *DirectKeyManager) ComputeCEK(_ context.Context, _ *jwa.JWH) ([]byte, error) {
	return manager.cek, nil
}

func (manager *DirectKeyManager) EncryptCEK(_ context.Context, _ *jwa.JWH, _ []byte) ([]byte, error) {
	return nil, nil
}

// DirectKeyDecoderConfig holds the shared content encryption key used to decrypt
// the token.
type DirectKeyDecoderConfig struct {
	CEK []byte
}

// DirectKeyDecoder implements jwe.CEKDecoder for direct encryption, returning the
// shared content encryption key it was configured with.
type DirectKeyDecoder struct {
	cek []byte
}

// NewDirectKeyDecoder creates a jwe.CEKDecoder that decrypts tokens with the given
// shared content encryption key.
//
// https://datatracker.ietf.org/doc/html/rfc7518#section-4.5
func NewDirectKeyDecoder(config *DirectKeyDecoderConfig) *DirectKeyDecoder {
	return &DirectKeyDecoder{
		cek: config.CEK,
	}
}

func (decoder *DirectKeyDecoder) ComputeCEK(_ context.Context, header *jwa.JWH, _ []byte) ([]byte, error) {
	if header.Alg != jwa.DIR {
		return nil, fmt.Errorf(
			"(DirectKeyDecoder.ComputeCEK) %w: invalid algorithm %s, expected %s",
			jwt.ErrMismatchRecipientPlugin, header.Alg, jwa.DIR,
		)
	}

	return decoder.cek, nil
}
