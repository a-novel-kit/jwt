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

// AESGCMPreset holds the parameters of one AES-GCM variant: the enc identifier and
// the key length. Use one of the package presets rather than assembling this by hand.
type AESGCMPreset struct {
	Enc    jwa.Enc
	KeyLen int
}

var (
	// A128GCM is AES-128-GCM.
	A128GCM = AESGCMPreset{
		Enc:    jwa.A128GCM,
		KeyLen: 16,
	}
	// A192GCM is AES-192-GCM.
	A192GCM = AESGCMPreset{
		Enc:    jwa.A192GCM,
		KeyLen: 24,
	}
	// A256GCM is AES-256-GCM.
	A256GCM = AESGCMPreset{
		Enc:    jwa.A256GCM,
		KeyLen: 32,
	}
)

// AESGCMEncryptionConfig configures NewAESGCMEncryption. CEKManager supplies the
// content encryption key; AdditionalData, when set, is authenticated but not encrypted.
type AESGCMEncryptionConfig struct {
	CEKManager     CEKManager
	AdditionalData []byte
}

// AESGCMEncryption is a jwt.ProducerPlugin that encrypts a token payload with
// AES-GCM. Create it with NewAESGCMEncryption.
type AESGCMEncryption struct {
	cekManager     CEKManager
	additionalData []byte

	enc       jwa.Enc
	keyLength int
}

// NewAESGCMEncryption creates a jwt.ProducerPlugin that encrypts a token payload
// with AES-GCM. Pass one of the package's AESGCMPreset values to select the key size.
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

	// A CEKManager may pin the token to a specific enc; honor that pin rather than override it.
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

	// A fresh random 96-bit nonce, the length NewGCM expects by default.
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

	// Seal appends the authentication tag to the ciphertext; JWE carries them in
	// separate fields, so split off the trailing Overhead() bytes.
	ciphertextAndTag := aesgcm.Seal(nil, iv, plainText, enc.additionalData)
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

// AESGCMDecryptionConfig configures NewAESGCMDecryption. CEKDecoder recovers the
// content encryption key; AdditionalData must equal the value used at encryption.
type AESGCMDecryptionConfig struct {
	CEKDecoder     CEKDecoder
	AdditionalData []byte
}

// AESGCMDecryption is a jwt.RecipientPlugin that decrypts a token encrypted with
// AES-GCM. Create it with NewAESGCMDecryption.
type AESGCMDecryption struct {
	cekDecoder     CEKDecoder
	additionalData []byte

	enc       jwa.Enc
	keyLength int
}

// NewAESGCMDecryption creates a jwt.RecipientPlugin that decrypts a token encrypted
// with AES-GCM. Pass one of the package's AESGCMPreset values to select the key size;
// it must match the one used at encryption.
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
