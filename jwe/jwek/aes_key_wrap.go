package jwek

import (
	"context"
	"crypto/aes"
	"fmt"

	"github.com/a-novel-kit/jwt"
	"github.com/a-novel-kit/jwt/jwa"
	"github.com/a-novel-kit/jwt/jwe/internal"
)

// AESKWPreset pairs a JWA algorithm identifier with its wrap-key length. Use one
// of the predefined presets rather than building one by hand.
type AESKWPreset struct {
	Alg    jwa.Alg
	KeyLen int
}

// The AES key-wrap presets, one per supported wrap-key length.
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

// AESKWManagerConfig holds the inputs for NewAESKWManager: the content encryption
// key to protect and the key that wraps it.
type AESKWManagerConfig struct {
	CEK     []byte
	WrapKey []byte
}

// AESKWManager implements jwe.CEKManager, wrapping the content encryption key with
// the AES Key Wrap algorithm. See RFC 7518 section 4.4.
type AESKWManager struct {
	cek     []byte
	wrapKey []byte

	alg    jwa.Alg
	keyLen int
}

// NewAESKWManager creates a jwe.CEKManager that wraps the content encryption key
// with AES Key Wrap. The preset selects the algorithm and wrap-key length; use one
// of the AESKWPreset values (for example A128KW).
//
// https://datatracker.ietf.org/doc/html/rfc7518#section-4.4
func NewAESKWManager(config *AESKWManagerConfig, preset AESKWPreset) *AESKWManager {
	return &AESKWManager{
		cek:     config.CEK,
		wrapKey: config.WrapKey,
		alg:     preset.Alg,
		keyLen:  preset.KeyLen,
	}
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

// AESKWDecoderConfig holds the key-wrapping key used to unwrap a content
// encryption key.
type AESKWDecoderConfig struct {
	WrapKey []byte
}

// AESKWDecoder implements jwe.CEKDecoder, unwrapping a content encryption key that
// was wrapped with AES Key Wrap.
type AESKWDecoder struct {
	wrapKey []byte

	alg    jwa.Alg
	keyLen int
}

// NewAESKWDecoder creates a jwe.CEKDecoder that unwraps an AES Key Wrap wrapped
// content encryption key. The preset must match the one used to wrap it; use one
// of the AESKWPreset values (for example A128KW).
//
// https://datatracker.ietf.org/doc/html/rfc7518#section-4.4
func NewAESKWDecoder(secret *AESKWDecoderConfig, preset AESKWPreset) *AESKWDecoder {
	return &AESKWDecoder{
		wrapKey: secret.WrapKey,
		alg:     preset.Alg,
		keyLen:  preset.KeyLen,
	}
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
