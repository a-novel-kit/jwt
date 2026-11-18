package jwe

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"slices"

	"github.com/a-novel-kit/jwt/v2"
	"github.com/a-novel-kit/jwt/v2/jwa"
)

// AESGCMPreset describes an AES-GCM variant. Use one of the package presets.
type AESGCMPreset struct {
	// Enc is the content encryption algorithm.
	Enc jwa.Enc
	// KeyLen is the length of the content encryption key, in bytes.
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

// AESGCMEncryptionConfig configures NewAESGCMEncryption.
type AESGCMEncryptionConfig struct {
	// CEKManager supplies the content encryption key and decides how it reaches the recipient.
	CEKManager CEKManager
	// AdditionalData is authenticated with the token without being encrypted. The recipient must
	// configure the same value.
	AdditionalData []byte
}

// AESGCMEncryption is a jwt.ProducerPlugin that encrypts a token payload with
// AES-GCM. Create it with NewAESGCMEncryption.
type AESGCMEncryption struct {
	contentEncryption
}

// NewAESGCMEncryption creates a jwt.ProducerPlugin that encrypts a token payload
// with AES-GCM. Pass one of the package's AESGCMPreset values to select the key size.
//
// https://datatracker.ietf.org/doc/html/rfc7518#section-5.3
func NewAESGCMEncryption(config *AESGCMEncryptionConfig, preset AESGCMPreset) *AESGCMEncryption {
	return &AESGCMEncryption{
		contentEncryption: contentEncryption{
			cekManager:     config.CEKManager,
			additionalData: config.AdditionalData,
			enc:            preset.Enc,
			cekLen:         preset.KeyLen,
		},
	}
}

func (enc *AESGCMEncryption) Transform(ctx context.Context, header *jwa.JWH, rawToken string) (string, error) {
	return enc.encrypt(ctx, header, rawToken, sealGCM)
}

// sealGCM encrypts plainText under a fresh random 96-bit nonce (RFC 7518 §5.3).
func sealGCM(cek, plainText, aadBytes []byte) ([]byte, []byte, []byte, error) {
	aesgcm, err := newGCM(cek)
	if err != nil {
		return nil, nil, nil, err
	}

	iv := make([]byte, aesgcm.NonceSize())
	_, _ = rand.Read(iv) // never fails: it crashes the program instead

	// Seal appends the authentication tag to the ciphertext, and JWE carries the two in separate
	// segments.
	sealed := aesgcm.Seal(nil, iv, plainText, aadBytes)
	cipherLen := len(sealed) - aesgcm.Overhead()

	return iv, sealed[:cipherLen], sealed[cipherLen:], nil
}

// AESGCMDecryptionConfig configures NewAESGCMDecryption.
type AESGCMDecryptionConfig struct {
	// CEKDecoder recovers the content encryption key from the token.
	CEKDecoder CEKDecoder
	// AdditionalData must equal the value the token was encrypted with.
	AdditionalData []byte
}

// AESGCMDecryption is a jwt.RecipientPlugin that decrypts a token encrypted with
// AES-GCM. Create it with NewAESGCMDecryption.
type AESGCMDecryption struct {
	contentDecryption
}

// NewAESGCMDecryption creates a jwt.RecipientPlugin that decrypts a token encrypted
// with AES-GCM. Pass one of the package's AESGCMPreset values to select the key size;
// it must match the one used at encryption.
//
// https://datatracker.ietf.org/doc/html/rfc7518#section-5.3
func NewAESGCMDecryption(config *AESGCMDecryptionConfig, preset AESGCMPreset) *AESGCMDecryption {
	return &AESGCMDecryption{
		contentDecryption: contentDecryption{
			cekDecoder:     config.CEKDecoder,
			additionalData: config.AdditionalData,
			enc:            preset.Enc,
			cekLen:         preset.KeyLen,
		},
	}
}

func (dec *AESGCMDecryption) Transform(ctx context.Context, header *jwa.JWH, rawToken string) ([]byte, error) {
	return dec.decrypt(ctx, header, rawToken, openGCM)
}

// openGCM decrypts the token's ciphertext and checks its tag (RFC 7518 §5.3).
func openGCM(cek []byte, segments *encryptedSegments, aadBytes []byte) ([]byte, error) {
	aesgcm, err := newGCM(cek)
	if err != nil {
		return nil, err
	}

	// The IV is attacker-supplied, and gcm.Open panics on a nonce of the wrong length.
	if len(segments.iv) != aesgcm.NonceSize() {
		return nil, fmt.Errorf("%w: iv length %d, expected %d", ErrInvalidToken, len(segments.iv), aesgcm.NonceSize())
	}

	// A tag of the wrong length makes the token malformed, which ErrInvalidToken reports apart from an
	// authentication failure.
	if len(segments.tag) != aesgcm.Overhead() {
		return nil, fmt.Errorf("%w: tag length %d, expected %d", ErrInvalidToken, len(segments.tag), aesgcm.Overhead())
	}

	plainText, err := aesgcm.Open(nil, segments.iv, slices.Concat(segments.cipherText, segments.tag), aadBytes)
	if err != nil {
		// An authenticated-decryption failure is the GCM analogue of a bad HMAC tag, so it surfaces
		// the same sentinel as the CBC path.
		return nil, fmt.Errorf("%w: %w: %w", jwt.ErrTokenRejected, ErrInvalidSecret, err)
	}

	return plainText, nil
}

// newGCM returns the AES-GCM cipher keyed with cek, with the 96-bit nonce and 128-bit tag RFC 7518
// §5.3 fixes.
func newGCM(cek []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create gcm: %w", err)
	}

	return aesgcm, nil
}
