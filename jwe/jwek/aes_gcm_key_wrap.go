package jwek

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"

	"github.com/a-novel-kit/jwt/v2"
	"github.com/a-novel-kit/jwt/v2/jwa"
)

var (
	// A128GCMKW wraps the content encryption key with AES-GCM under a 16-byte key.
	A128GCMKW = KeyWrapPreset{
		Alg:    jwa.A128GCMKW,
		KeyLen: 16,
	}
	// A192GCMKW wraps the content encryption key with AES-GCM under a 24-byte key.
	A192GCMKW = KeyWrapPreset{
		Alg:    jwa.A192GCMKW,
		KeyLen: 24,
	}
	// A256GCMKW wraps the content encryption key with AES-GCM under a 32-byte key.
	A256GCMKW = KeyWrapPreset{
		Alg:    jwa.A256GCMKW,
		KeyLen: 32,
	}
)

// AESGCMKWManagerConfig configures NewAESGCMKWManager.
type AESGCMKWManagerConfig struct {
	// Deprecated: ignored. Each token is encrypted under a fresh random content encryption key, as
	// RFC 7516 requires.
	CEK []byte
	// WrapKey is the AES key that wraps each token's content encryption key. Its length matches the
	// preset's.
	WrapKey []byte
}

// AESGCMKWManager implements jwe.CEKManager, wrapping the content encryption key
// with AES GCM. See RFC 7518 section 4.7.
type AESGCMKWManager struct {
	wrapKey []byte

	alg    jwa.Alg
	keyLen int
}

// NewAESGCMKWManager creates a jwe.CEKManager that wraps the content encryption
// key with AES GCM. The preset selects the algorithm and wrap-key length; use one
// of the KeyWrapPreset values (for example A128GCMKW).
//
// https://datatracker.ietf.org/doc/html/rfc7518#section-4.7
func NewAESGCMKWManager(
	config *AESGCMKWManagerConfig, preset KeyWrapPreset,
) *AESGCMKWManager {
	return &AESGCMKWManager{
		wrapKey: config.WrapKey,
		alg:     preset.Alg,
		keyLen:  preset.KeyLen,
	}
}

func (manager *AESGCMKWManager) SetHeader(_ context.Context, header *jwa.JWH) (*jwa.JWH, error) {
	if !header.Alg.Empty() {
		return nil, fmt.Errorf("(AESGCMKWManager.SetHeader) %w: alg field already set", jwt.ErrConflictingHeader)
	}

	header.Alg = manager.alg

	return header, nil
}

func (manager *AESGCMKWManager) ComputeCEK(_ context.Context, header *jwa.JWH) ([]byte, error) {
	cek, err := newCEK(header)
	if err != nil {
		return nil, fmt.Errorf("(AESGCMKWManager.ComputeCEK) %w", err)
	}

	return cek, nil
}

func (manager *AESGCMKWManager) EncryptCEK(_ context.Context, header *jwa.JWH, cek []byte) ([]byte, error) {
	if len(manager.wrapKey) != manager.keyLen {
		return nil, fmt.Errorf(
			"(AESGCMKWManager.EncryptCEK) invalid wrap key length: expected %d, got %d",
			manager.keyLen, len(manager.wrapKey),
		)
	}

	block, err := aes.NewCipher(manager.wrapKey)
	if err != nil {
		return nil, fmt.Errorf("(AESGCMKWManager.EncryptCEK) create cipher: %w", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("(AESGCMKWManager.EncryptCEK) create AEAD: %w", err)
	}

	iv := make([]byte, aesgcm.NonceSize())

	_, err = io.ReadFull(rand.Reader, iv)
	if err != nil {
		return nil, fmt.Errorf("(AESGCMKWManager.EncryptCEK) generate IV: %w", err)
	}

	ciphertextAndTag := aesgcm.Seal(nil, iv, cek, []byte{})
	// Seal appends the authentication tag to the ciphertext, and the JWE header carries the tag
	// separately.
	cipherLen := len(ciphertextAndTag) - aesgcm.Overhead()
	ciphertext := ciphertextAndTag[:cipherLen]
	tag := ciphertextAndTag[cipherLen:]

	if len(iv) != 12 {
		return nil, fmt.Errorf("(AESGCMKWManager.EncryptCEK) invalid IV size: expected 12, got %d", len(iv))
	}

	if len(tag) != 16 {
		return nil, fmt.Errorf("(AESGCMKWManager.EncryptCEK) invalid tag size: expected 16, got %d", len(tag))
	}

	header.JWHAESGCMKW = jwa.JWHAESGCMKW{
		IV:  base64.RawURLEncoding.EncodeToString(iv),
		Tag: base64.RawURLEncoding.EncodeToString(tag),
	}

	return ciphertext, nil
}

// AESGCMKWDecoderConfig configures NewAESGCMKWDecoder.
type AESGCMKWDecoderConfig struct {
	// WrapKey is the AES key the content encryption key was wrapped under.
	WrapKey []byte
}

// AESGCMKWDecoder implements jwe.CEKDecoder, unwrapping a content encryption key
// that was wrapped with AES GCM.
type AESGCMKWDecoder struct {
	wrapKey []byte
	alg     jwa.Alg
	keyLen  int
}

// NewAESGCMKWDecoder creates a jwe.CEKDecoder that unwraps an AES GCM wrapped
// content encryption key. The preset must match the one used to wrap it; use one
// of the KeyWrapPreset values (for example A128GCMKW).
//
// https://datatracker.ietf.org/doc/html/rfc7518#section-4.7
func NewAESGCMKWDecoder(config *AESGCMKWDecoderConfig, preset KeyWrapPreset) *AESGCMKWDecoder {
	return &AESGCMKWDecoder{
		wrapKey: config.WrapKey,
		alg:     preset.Alg,
		keyLen:  preset.KeyLen,
	}
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
		return nil, fmt.Errorf("(AESGCMKWDecoder.ComputeCEK) %w: decode IV: %w", jwt.ErrUnsupportedTokenFormat, err)
	}

	tag, err := base64.RawURLEncoding.DecodeString(header.Tag)
	if err != nil {
		return nil, fmt.Errorf("(AESGCMKWDecoder.ComputeCEK) %w: decode tag: %w", jwt.ErrUnsupportedTokenFormat, err)
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
