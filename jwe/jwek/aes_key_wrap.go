package jwek

import (
	"context"
	"crypto/aes"
	"fmt"

	"github.com/a-novel-kit/jwt"
	"github.com/a-novel-kit/jwt/jwa"
	"github.com/a-novel-kit/jwt/jwe/internal"
)

type AESKWPreset struct {
	Alg    jwa.Alg
	KeyLen int
}

var (
	A128KW = AESKWPreset{
		Alg:    jwa.A128KW,
		KeyLen: 16,
	}
	A192KW = AESKWPreset{
		Alg:    jwa.A192KW,
		KeyLen: 24,
	}
	A256KW = AESKWPreset{
		Alg:    jwa.A256KW,
		KeyLen: 32,
	}
)

type AESKWManagerConfig struct {
	CEK     []byte
	WrapKey []byte
}

type AESKWManager struct {
	cek     []byte
	wrapKey []byte

	alg    jwa.Alg
	keyLen int
}

func (manager *AESKWManager) SetHeader(_ context.Context, header *jwa.JWH) (*jwa.JWH, error) {
	if !header.Alg.Empty() {
		return nil, fmt.Errorf("(AESKW.SetHeader) %w: alg field already set", jwt.ErrConflictingHeader)
	}

	header.Alg = manager.alg

	return header, nil
}

func (manager *AESKWManager) ComputeCEK(_ context.Context, _ *jwa.JWH) ([]byte, error) {
	return manager.cek, nil
}

func (manager *AESKWManager) EncryptCEK(_ context.Context, _ *jwa.JWH, cek []byte) ([]byte, error) {
	if len(manager.wrapKey) != manager.keyLen {
		return nil, fmt.Errorf(
			"(AESKW.EncryptCEK) invalid wrap key length: expected %d, got %d",
			manager.keyLen, len(manager.wrapKey),
		)
	}

	block, err := aes.NewCipher(manager.wrapKey)
	if err != nil {
		return nil, fmt.Errorf("(AESKWManager.EncryptCEK) create cipher: %w", err)
	}

	wrapped, err := internal.KeyWrap(block, cek)
	if err != nil {
		return nil, fmt.Errorf("(AESKWManager.EncryptCEK) wrap key: %w", err)
	}

	return wrapped, nil
}

// NewAESKWManager creates a new jwe.CEKManager for a key derived using AES Key Wrap.
//
// Use any of the AESKWPreset constants to set the algorithm and key length.
//   - A128KW: 16 bytes key length
//   - A192KW: 24 bytes key length
//   - A256KW: 32 bytes key length
//
// https://datatracker.ietf.org/doc/html/rfc7518#section-4.4
func NewAESKWManager(secret *AESKWManagerConfig, preset AESKWPreset) *AESKWManager {
	return &AESKWManager{
		cek:     secret.CEK,
		wrapKey: secret.WrapKey,
		alg:     preset.Alg,
		keyLen:  preset.KeyLen,
	}
}

type AESKWDecoderConfig struct {
	WrapKey []byte
}

type AESKWDecoder struct {
	wrapKey []byte

	alg    jwa.Alg
	keyLen int
}

func (decoder *AESKWDecoder) ComputeCEK(_ context.Context, header *jwa.JWH, encKey []byte) ([]byte, error) {
	if header.Alg != decoder.alg {
		return nil, fmt.Errorf(
			"(AESKWDecoder.ComputeCEK) %w: invalid algorithm %s, expected %s",
			jwt.ErrMismatchRecipientPlugin, header.Alg, decoder.alg,
		)
	}

	if len(decoder.wrapKey) != decoder.keyLen {
		return nil, fmt.Errorf(
			"(AESKWDecoder.ComputeCEK) invalid wrap key length: expected %d, got %d",
			decoder.keyLen, len(decoder.wrapKey),
		)
	}

	if len(encKey) == 0 {
		return nil, fmt.Errorf(
			"(AESKWDecoder.ComputeCEK) %w: unexpected enc key (should not be empty)",
			jwt.ErrUnsupportedTokenFormat,
		)
	}

	block, err := aes.NewCipher(decoder.wrapKey)
	if err != nil {
		return nil, fmt.Errorf("(AESKWDecoder.ComputeCEK) create cipher: %w", err)
	}

	cek, err := internal.KeyUnwrap(block, encKey)
	if err != nil {
		return nil, fmt.Errorf("(AESKWDecoder.ComputeCEK) unwrap key: %w", err)
	}

	return cek, nil
}

// NewAESKWDecoder creates a new jwe.CEKDecoder for a key derived using AES Key Wrap.
//
// Use any of the AESKWPreset constants to set the algorithm and key length.
//   - A128KW: 16 bytes key length
//   - A192KW: 24 bytes key length
//   - A256KW: 32 bytes key length
//
// https://datatracker.ietf.org/doc/html/rfc7518#section-4.4
func NewAESKWDecoder(secret *AESKWDecoderConfig, preset AESKWPreset) *AESKWDecoder {
	return &AESKWDecoder{
		wrapKey: secret.WrapKey,
		alg:     preset.Alg,
		keyLen:  preset.KeyLen,
	}
}
