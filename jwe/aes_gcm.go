package jwe

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/a-novel-kit/jwt"
	"github.com/a-novel-kit/jwt/jwa"
)

type AESGCMPreset struct {
	Enc    jwa.Enc
	KeyLen int
}

var (
	A128GCM = AESGCMPreset{
		Enc:    jwa.A128GCM,
		KeyLen: 16,
	}
	A192GCM = AESGCMPreset{
		Enc:    jwa.A192GCM,
		KeyLen: 24,
	}
	A256GCM = AESGCMPreset{
		Enc:    jwa.A256GCM,
		KeyLen: 32,
	}
)

type AESGCMEncryptionConfig struct {
	CEKManager     CEKManager
	AdditionalData []byte
}

type AESGCMEncryption struct {
	cekManager     CEKManager
	additionalData []byte

	enc       jwa.Enc
	keyLength int
}

// NewAESGCMEncryption creates a new jwt.ProducerPlugin for an encrypted token using AES-GCM.
//
// Use any of the AESGCMPreset constants to set the algorithm and hash function.
//   - A128GCM: AES-128-GCM
//   - A192GCM: AES-192-GCM
//   - A256GCM: AES-256-GCM
func NewAESGCMEncryption(config *AESGCMEncryptionConfig, presets AESGCMPreset) *AESGCMEncryption {
	return &AESGCMEncryption{
		cekManager:     config.CEKManager,
		additionalData: config.AdditionalData,
		enc:            presets.Enc,
		keyLength:      presets.KeyLen,
	}
}

func (enc *AESGCMEncryption) Header(ctx context.Context, header *jwa.JWH) (*jwa.JWH, error) {
	if header.Enc != "" {
		return nil, fmt.Errorf("(AESGCMEncryption.Header) %w: enc field already set", jwt.ErrConflictingHeader)
	}

	var err error

	header, err = enc.cekManager.SetHeader(ctx, header)
	if err != nil {
		return nil, fmt.Errorf("(AESGCMEncryption.Header) set key derivation header: %w", err)
	}

	// If the CEK CEKManager specifies an explicit enc compatibility, it must be respected.
	if header.Enc != "" && header.Enc != enc.enc {
		return nil, fmt.Errorf(
			"(AESGCMEncryption.Header) %w: cek manager is incompatible with the current encryption algorithm: "+
				"expected %s, got %s",
			jwt.ErrConflictingHeader, enc.enc, header.Enc,
		)
	}

	header.Enc = enc.enc

	return header, nil
}

func (enc *AESGCMEncryption) Transform(ctx context.Context, header *jwa.JWH, rawToken string) (string, error) {
	token, err := jwt.DecodeToken(rawToken, &jwt.RawTokenDecoder{})
	if err != nil {
		return "", fmt.Errorf("(AESGCMEncryption.Transform) split token: %w", err)
	}

	plainText, err := base64.RawURLEncoding.DecodeString(token.Payload)
	if err != nil {
		return "", fmt.Errorf("(AESGCMEncryption.Transform) decode payload: %w", err)
	}

	secret, err := enc.getCEK(ctx, header)
	if err != nil {
		return "", fmt.Errorf("(AESGCMEncryption.Transform) get secret key: %w", err)
	}

	encryptedSecret, err := enc.cekManager.EncryptCEK(ctx, header, secret)
	if err != nil {
		return "", fmt.Errorf("(AESGCMEncryption.Transform) encrypt key: %w", err)
	}

	// The IV used is a 128-bit value generated randomly or pseudorandomly for use in the cipher.
	iv := make([]byte, 12)

	_, err = rand.Read(iv)
	if err != nil {
		return "", fmt.Errorf("(AESGCMEncryption.Transform) generate IV: %w", err)
	}

	block, err := aes.NewCipher(secret)
	if err != nil {
		return "", fmt.Errorf("(AESGCMEncryption.Transform) create cipher: %w", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("(AESGCMEncryption.Transform) create gcm: %w", err)
	}

	ciphertextAndTag := aesgcm.Seal(nil, iv, plainText, enc.additionalData)
	// Separate the actual cipherText from the authentication tag.
	cipherLen := len(ciphertextAndTag) - aesgcm.Overhead()
	cipherText := ciphertextAndTag[:cipherLen]
	tag := ciphertextAndTag[cipherLen:]

	if len(tag) != 16 {
		return "", fmt.Errorf("(AESGCMEncryption.Transform) invalid tag size: expected 16, got %d", len(tag))
	}

	return jwt.EncryptedToken{
		Header:     token.Header,
		EncKey:     base64.RawURLEncoding.EncodeToString(encryptedSecret),
		IV:         base64.RawURLEncoding.EncodeToString(iv),
		CipherText: base64.RawURLEncoding.EncodeToString(cipherText),
		Tag:        base64.RawURLEncoding.EncodeToString(tag),
	}.String(), nil
}

func (enc *AESGCMEncryption) getCEK(ctx context.Context, header *jwa.JWH) ([]byte, error) {
	secret, err := enc.cekManager.ComputeCEK(ctx, header)
	if err != nil {
		return nil, fmt.Errorf("(AESGCMEncryption.getCEK) compute cek: %w", err)
	}

	if len(secret) != enc.keyLength {
		return nil, fmt.Errorf(
			"(AESGCMEncryption.getCEK) %w: cek has length %d, expected %d",
			ErrInvalidSecret, len(secret), enc.keyLength,
		)
	}

	return secret, nil
}

type AESGCMDecryptionConfig struct {
	CEKDecoder     CEKDecoder
	AdditionalData []byte
}

type AESGCMDecryption struct {
	cekDecoder     CEKDecoder
	additionalData []byte

	enc       jwa.Enc
	keyLength int
}

// NewAESGCMDecryption creates a new jwt.RecipientPlugin for an encrypted token using AES-GCM.
//
// Use any of the AESGCMPreset constants to set the algorithm and hash function.
//   - A128GCM: AES-128-GCM
//   - A192GCM: AES-192-GCM
//   - A256GCM: AES-256-GCM
func NewAESGCMDecryption(config *AESGCMDecryptionConfig, presets AESGCMPreset) *AESGCMDecryption {
	return &AESGCMDecryption{
		cekDecoder:     config.CEKDecoder,
		additionalData: config.AdditionalData,
		enc:            presets.Enc,
		keyLength:      presets.KeyLen,
	}
}

func (dec *AESGCMDecryption) Transform(ctx context.Context, header *jwa.JWH, rawToken string) ([]byte, error) {
	if header.Enc != dec.enc {
		return nil, fmt.Errorf(
			"(AESGCMDecryption.Transform) %w: invalid enc %s, expected %s",
			jwt.ErrMismatchRecipientPlugin, header.Enc, dec.enc,
		)
	}

	token, err := jwt.DecodeToken(rawToken, &jwt.EncryptedTokenDecoder{})
	if err != nil {
		return nil, fmt.Errorf("(AESGCMDecryption.Transform) split token: %w", err)
	}

	var encryptedKey []byte
	if len(token.EncKey) > 0 {
		encryptedKey, err = base64.RawURLEncoding.DecodeString(token.EncKey)
	}

	if err != nil {
		return nil, fmt.Errorf("(AESGCMDecryption.Transform) decode enc key: %w", err)
	}

	iv, err := base64.RawURLEncoding.DecodeString(token.IV)
	if err != nil {
		return nil, fmt.Errorf("(AESGCMDecryption.Transform) decode iv: %w", err)
	}

	tag, err := base64.RawURLEncoding.DecodeString(token.Tag)
	if err != nil {
		return nil, fmt.Errorf("(AESGCMDecryption.Transform) decode tag: %w", err)
	}

	cipherText, err := base64.RawURLEncoding.DecodeString(token.CipherText)
	if err != nil {
		return nil, fmt.Errorf("(AESGCMDecryption.Transform) decode cipher text: %w", err)
	}

	cek, err := dec.cekDecoder.ComputeCEK(ctx, header, encryptedKey)
	if err != nil {
		return nil, fmt.Errorf("(AESGCMDecryption.Transform) get secret key: %w", err)
	}

	if len(cek) != dec.keyLength {
		return nil, fmt.Errorf(
			"(AESGCMDecryption.Transform) %w: cek has length %d, expected %d",
			ErrInvalidSecret, len(cek), dec.keyLength,
		)
	}

	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, fmt.Errorf("(AESGCMDecryption.Transform) create cipher: %w", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("(AESGCMDecryption.Transform) create gcm: %w", err)
	}

	if len(cipherText)+len(tag) < aesgcm.NonceSize() {
		return nil, errors.New("(AESGCMDecryption.Transform) ciphertext too short")
	}

	plainText, err := aesgcm.Open(nil, iv, append(cipherText, tag...), dec.additionalData)
	if err != nil {
		return nil, fmt.Errorf("(AESGCMDecryption.Transform) decrypt: %w", err)
	}

	return plainText, nil
}
