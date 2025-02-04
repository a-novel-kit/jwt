package jwek

import (
	"context"
	"fmt"

	"github.com/a-novel-kit/jwt"
	"github.com/a-novel-kit/jwt/jwa"
)

type DirectKeyManager struct {
	cek []byte
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

func (manager *DirectKeyManager) EncryptCEK(_ context.Context, _ []byte) ([]byte, error) {
	return nil, nil
}

// NewDirectKeyManager creates a new instance of DirectKeyManager.
//
// https://datatracker.ietf.org/doc/html/rfc7518#section-4.5
func NewDirectKeyManager(cek []byte) *DirectKeyManager {
	return &DirectKeyManager{
		cek: cek,
	}
}

type DirectKeyDecoderConfig struct {
	CEK []byte
}

type DirectKeyDecoder struct {
	cek []byte
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

// NewDirectKeyDecoder creates a new instance of DirectKeyDecoder.
//
// https://datatracker.ietf.org/doc/html/rfc7518#section-4.5
func NewDirectKeyDecoder(config *DirectKeyDecoderConfig) *DirectKeyDecoder {
	return &DirectKeyDecoder{
		cek: config.CEK,
	}
}
