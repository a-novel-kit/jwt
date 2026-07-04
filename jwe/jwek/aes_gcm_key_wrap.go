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

// AESGCMKWPreset pairs a JWA algorithm identifier with its wrap-key length. Use
// one of the predefined presets rather than building one by hand.
type AESGCMKWPreset struct {
	Alg    jwa.Alg
	KeyLen int
}

// The AES GCM key-wrap presets, one per supported wrap-key length.
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

// AESGCMKWManagerConfig holds the inputs for NewAESGCMKWManager: the content
// encryption key to protect and the key that wraps it.
type AESGCMKWManagerConfig struct {
	CEK     []byte
	WrapKey []byte
}

// AESGCMKWManager implements jwe.CEKManager, wrapping the content encryption key
// with AES GCM. See RFC 7518 section 4.7.
type AESGCMKWManager struct {
	cek     []byte
	wrapKey []byte

	alg    jwa.Alg
	keyLen int
}

// NewAESGCMKWManager creates a jwe.CEKManager that wraps the content encryption
// key with AES GCM. The preset selects the algorithm and wrap-key length; use one
// of the AESGCMKWPreset values (for example A128GCMKW).
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
	// Seal appends the authentication tag to the ciphertext; the JWE header carries
	// the tag separately, so split the two apart here.
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

// AESGCMKWDecoderConfig holds the key-wrapping key used to unwrap a content
// encryption key.
type AESGCMKWDecoderConfig struct {
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
// of the AESGCMKWPreset values (for example A128GCMKW).
//
// https://datatracker.ietf.org/doc/html/rfc7518#section-4.7
func NewAESGCMKWDecoder(config *AESGCMKWDecoderConfig, preset AESGCMKWPreset) *AESGCMKWDecoder {
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
