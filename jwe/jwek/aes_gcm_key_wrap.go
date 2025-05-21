package jwek

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"

	"github.com/a-novel-kit/jwt"
	"github.com/a-novel-kit/jwt/jwa"
)

type AESGCMKWPreset struct {
	Alg    jwa.Alg
	KeyLen int
}

var (
	A128GCMKW = AESGCMKWPreset{
		Alg:    jwa.A128GCMKW,
		KeyLen: 16,
	}
	A192GCMKW = AESGCMKWPreset{
		Alg:    jwa.A192GCMKW,
		KeyLen: 24,
	}
	A256GCMKW = AESGCMKWPreset{
		Alg:    jwa.A256GCMKW,
		KeyLen: 32,
	}
)

type AESGCMKWManagerConfig struct {
	CEK     []byte
	WrapKey []byte
}

type AESGCMKWManager struct {
	cek     []byte
	wrapKey []byte

	alg    jwa.Alg
	keyLen int
}

func (manager *AESGCMKWManager) SetHeader(_ context.Context, header *jwa.JWH) (*jwa.JWH, error) {
	if !header.Alg.Empty() {
		return nil, fmt.Errorf("(AESGCMKW.SetHeader) %w: alg field already set", jwt.ErrConflictingHeader)
	}

	header.Alg = manager.alg

	return header, nil
}

func (manager *AESGCMKWManager) ComputeCEK(_ context.Context, _ *jwa.JWH) ([]byte, error) {
	return manager.cek, nil
}

func (manager *AESGCMKWManager) EncryptCEK(_ context.Context, header *jwa.JWH, cek []byte) ([]byte, error) {
	if len(manager.wrapKey) != manager.keyLen {
		return nil, fmt.Errorf(
			"(AESGCMKW.EncryptCEK) invalid wrap key length: expected %d, got %d",
			manager.keyLen, len(manager.wrapKey),
		)
	}

	block, err := aes.NewCipher(manager.wrapKey)
	if err != nil {
		return nil, fmt.Errorf("(AESGCMKW.EncryptCEK) create cipher: %w", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("(AESGCMKW.EncryptCEK) create AEAD: %w", err)
	}

	iv := make([]byte, aesgcm.NonceSize())

	_, err = io.ReadFull(rand.Reader, iv)
	if err != nil {
		return nil, fmt.Errorf("(AESGCMKW.EncryptCEK) generate IV: %w", err)
	}

	ciphertextAndTag := aesgcm.Seal(nil, iv, cek, []byte{})
	// Separate the actual cipherText from the authentication tag.
	cipherLen := len(ciphertextAndTag) - aesgcm.Overhead()
	ciphertext := ciphertextAndTag[:cipherLen]
	tag := ciphertextAndTag[cipherLen:]

	if len(iv) != 12 {
		return nil, fmt.Errorf("(AESGCMKW.EncryptCEK) invalid IV size: expected 12, got %d", len(iv))
	}

	if len(tag) != 16 {
		return nil, fmt.Errorf("(AESGCMKW.EncryptCEK) invalid tag size: expected 16, got %d", len(tag))
	}

	header.JWHAESGCMKW = jwa.JWHAESGCMKW{
		IV:  base64.RawURLEncoding.EncodeToString(iv),
		Tag: base64.RawURLEncoding.EncodeToString(tag),
	}

	return ciphertext, nil
}

// NewAESGCMKWManager creates a new jwe.CEKManager for a key derived using AES GCM Key Wrap.
//
// Use any of the AESGCMKWPreset constants to set the algorithm and key length.
//   - A128GCMKW: 16 bytes key length
//   - A192GCMKW: 24 bytes key length
//   - A256GCMKW: 32 bytes key length
//
// https://datatracker.ietf.org/doc/html/rfc7518#section-4.7
func NewAESGCMKWManager(
	config *AESGCMKWManagerConfig, preset AESGCMKWPreset,
) *AESGCMKWManager {
	return &AESGCMKWManager{
		cek:     config.CEK,
		wrapKey: config.WrapKey,
		alg:     preset.Alg,
		keyLen:  preset.KeyLen,
	}
}

type AESGCMKWDecoderConfig struct {
	WrapKey []byte
}

type AESGCMKWDecoder struct {
	wrapKey []byte
	alg     jwa.Alg
	keyLen  int
}

func (decoder *AESGCMKWDecoder) ComputeCEK(_ context.Context, header *jwa.JWH, encKey []byte) ([]byte, error) {
	if header.Alg != decoder.alg {
		return nil, fmt.Errorf(
			"(AESGCMKWDecoder.ComputeCEK) %w: invalid algorithm %s, expected %s",
			jwt.ErrMismatchRecipientPlugin, header.Alg, decoder.alg,
		)
	}

	if len(decoder.wrapKey) != decoder.keyLen {
		return nil, fmt.Errorf(
			"(AESGCMKWDecoder.ComputeCEK) invalid wrap key length: expected %d, got %d",
			decoder.keyLen, len(decoder.wrapKey),
		)
	}

	if len(encKey) == 0 {
		return nil, fmt.Errorf(
			"(AESGCMKWDecoder.ComputeCEK) %w: unexpected enc key (should not be empty)",
			jwt.ErrUnsupportedTokenFormat,
		)
	}

	iv, err := base64.RawURLEncoding.DecodeString(header.IV)
	if err != nil {
		return nil, fmt.Errorf("(AESGCMKWDecoder.ComputeCEK) decode IV: %w", err)
	}

	tag, err := base64.RawURLEncoding.DecodeString(header.Tag)
	if err != nil {
		return nil, fmt.Errorf("(AESGCMKWDecoder.ComputeCEK) decode tag: %w", err)
	}

	if len(iv) != 12 {
		return nil, fmt.Errorf("(AESGCMKWDecoder.ComputeCEK) invalid IV size: expected 12, got %d", len(iv))
	}

	if len(tag) != 16 {
		return nil, fmt.Errorf("(AESGCMKWDecoder.ComputeCEK) invalid tag size: expected 16, got %d", len(tag))
	}

	block, err := aes.NewCipher(decoder.wrapKey)
	if err != nil {
		return nil, fmt.Errorf("(AESGCMKWDecoder.ComputeCEK) create cipher: %w", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("(AESGCMKWDecoder.ComputeCEK) create AEAD: %w", err)
	}

	cek, err := aesgcm.Open(nil, iv, append(encKey, tag...), []byte{})
	if err != nil {
		return nil, fmt.Errorf("(AESGCMKWDecoder.ComputeCEK) decrypt CEK: %w", err)
	}

	return cek, nil
}

// NewAESGCMKWDecoder creates a new jwe.CEKDecoder for a key derived using AES GCM Key Wrap.
//
// Use any of the AESGCMKWPreset constants to set the algorithm and key length.
//   - A128GCMKW: 16 bytes key length
//   - A192GCMKW: 24 bytes key length
//   - A256GCMKW: 32 bytes key length
//
// https://datatracker.ietf.org/doc/html/rfc7518#section-4.7
func NewAESGCMKWDecoder(config *AESGCMKWDecoderConfig, preset AESGCMKWPreset) *AESGCMKWDecoder {
	return &AESGCMKWDecoder{
		wrapKey: config.WrapKey,
		alg:     preset.Alg,
		keyLen:  preset.KeyLen,
	}
}
