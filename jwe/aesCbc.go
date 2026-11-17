package jwe

import (
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"github.com/a-novel-kit/jwt/v2"
	"github.com/a-novel-kit/jwt/v2/jwa"
	"github.com/a-novel-kit/jwt/v2/jwe/internal"
)

// AESCBCPreset describes an AES_CBC_HMAC_SHA2 variant. Use one of the package presets.
type AESCBCPreset struct {
	// Enc is the content encryption algorithm.
	Enc jwa.Enc
	// Hash is the hash of the HMAC.
	Hash crypto.Hash
	// KeyLen is the length of the whole content encryption key, in bytes.
	KeyLen int
	// EncKeyLen is the length of the AES key, the trailing part of the content encryption key.
	EncKeyLen int
	// MACKeyLen is the length of the HMAC key, the leading part of the content encryption key.
	MACKeyLen int
	// TagLength is the length the authentication tag is truncated to, in bytes.
	TagLength int
}

var (
	// A128CBCHS256 is AES-128-CBC with HMAC-SHA-256.
	A128CBCHS256 = AESCBCPreset{
		Enc:       jwa.A128CBC,
		Hash:      crypto.SHA256,
		KeyLen:    32,
		EncKeyLen: 16,
		MACKeyLen: 16,
		TagLength: 16,
	}
	// A192CBCHS384 is AES-192-CBC with HMAC-SHA-384.
	A192CBCHS384 = AESCBCPreset{
		Enc:       jwa.A192CBC,
		Hash:      crypto.SHA384,
		KeyLen:    48,
		EncKeyLen: 24,
		MACKeyLen: 24,
		TagLength: 24,
	}
	// A256CBCHS512 is AES-256-CBC with HMAC-SHA-512.
	A256CBCHS512 = AESCBCPreset{
		Enc:       jwa.A256CBC,
		Hash:      crypto.SHA512,
		KeyLen:    64,
		EncKeyLen: 32,
		MACKeyLen: 32,
		TagLength: 32,
	}
)

// AESCBCEncryptionConfig configures NewAESCBCEncryption.
type AESCBCEncryptionConfig struct {
	// CEKManager supplies the content encryption key and decides how it reaches the recipient.
	CEKManager CEKManager
	// AdditionalData is authenticated with the token without being encrypted. The recipient must
	// configure the same value.
	AdditionalData []byte
}

// AESCBCEncryption is a jwt.ProducerPlugin that encrypts a token payload with
// AES_CBC_HMAC_SHA2. Create it with NewAESCBCEncryption.
type AESCBCEncryption struct {
	contentEncryption

	preset AESCBCPreset
}

// NewAESCBCEncryption creates a jwt.ProducerPlugin that encrypts a token payload
// with AES_CBC_HMAC_SHA2. Pass one of the package's AESCBCPreset values to select
// the variant.
//
// https://datatracker.ietf.org/doc/html/rfc7518#section-5.2
func NewAESCBCEncryption(config *AESCBCEncryptionConfig, preset AESCBCPreset) *AESCBCEncryption {
	return &AESCBCEncryption{
		contentEncryption: contentEncryption{
			cekManager:     config.CEKManager,
			additionalData: config.AdditionalData,
			enc:            preset.Enc,
			cekLen:         preset.MACKeyLen + preset.EncKeyLen,
		},
		preset: preset,
	}
}

func (enc *AESCBCEncryption) Transform(ctx context.Context, header *jwa.JWH, rawToken string) (string, error) {
	return enc.encrypt(ctx, header, rawToken, enc.seal)
}

// seal encrypts plainText under a fresh random 128-bit IV and computes its tag (RFC 7518 §5.2.2.1).
func (enc *AESCBCEncryption) seal(cek, plainText, aadBytes []byte) ([]byte, []byte, []byte, error) {
	// K splits into two subkeys: MAC_KEY is its leading octets, ENC_KEY its trailing
	// octets. The MAC key comes first, the reverse of the order the name suggests in
	// "AES_CBC_HMAC_SHA2".
	macKey, encKey := cek[:enc.preset.MACKeyLen], cek[enc.preset.MACKeyLen:]

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("new cipher: %w", err)
	}

	iv := make([]byte, aes.BlockSize)
	_, _ = rand.Read(iv) // never fails: it crashes the program instead

	// CBC encrypts in place, over the fresh slice the padding returns.
	cipherText := internal.PKCS7Padding(plainText, aes.BlockSize)
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(cipherText, cipherText)

	return iv, cipherText, cbcTag(enc.preset.Hash, macKey, aadBytes, iv, cipherText, enc.preset.TagLength), nil
}

// AESCBCDecryptionConfig configures NewAESCBCDecryption.
type AESCBCDecryptionConfig struct {
	// CEKDecoder recovers the content encryption key from the token.
	CEKDecoder CEKDecoder
	// AdditionalData must equal the value the token was encrypted with.
	AdditionalData []byte
}

// AESCBCDecryption is a jwt.RecipientPlugin that decrypts a token encrypted with
// AES_CBC_HMAC_SHA2. Create it with NewAESCBCDecryption.
type AESCBCDecryption struct {
	contentDecryption

	preset AESCBCPreset
}

// NewAESCBCDecryption creates a jwt.RecipientPlugin that decrypts a token encrypted
// with AES_CBC_HMAC_SHA2. Pass one of the package's AESCBCPreset values to select the
// variant; it must match the one used at encryption.
//
// https://datatracker.ietf.org/doc/html/rfc7518#section-5.2
func NewAESCBCDecryption(config *AESCBCDecryptionConfig, preset AESCBCPreset) *AESCBCDecryption {
	return &AESCBCDecryption{
		contentDecryption: contentDecryption{
			cekDecoder:     config.CEKDecoder,
			additionalData: config.AdditionalData,
			enc:            preset.Enc,
			cekLen:         preset.MACKeyLen + preset.EncKeyLen,
		},
		preset: preset,
	}
}

func (dec *AESCBCDecryption) Transform(ctx context.Context, header *jwa.JWH, rawToken string) ([]byte, error) {
	return dec.decrypt(ctx, header, rawToken, dec.open)
}

// open checks the token's tag, then decrypts and unpads its ciphertext (RFC 7518 §5.2.2.2).
func (dec *AESCBCDecryption) open(cek []byte, segments *encryptedSegments, aadBytes []byte) ([]byte, error) {
	// The IV and ciphertext are attacker-supplied, and the CBC decrypter panics unless the IV is one
	// block and the ciphertext whole blocks. A sender who knows the CEK passes the tag check with
	// either, so the lengths are checked first.
	if len(segments.iv) != aes.BlockSize {
		return nil, fmt.Errorf("%w: iv length %d, expected %d", ErrInvalidToken, len(segments.iv), aes.BlockSize)
	}

	if len(segments.cipherText)%aes.BlockSize != 0 {
		return nil, fmt.Errorf(
			"%w: cipher text length %d is not a multiple of %d", ErrInvalidToken, len(segments.cipherText), aes.BlockSize,
		)
	}

	// MAC_KEY leads K and ENC_KEY trails it, as at encryption.
	macKey, encKey := cek[:dec.preset.MACKeyLen], cek[dec.preset.MACKeyLen:]

	// The tag is checked before the ciphertext is touched. hmac.Equal compares in constant time, so
	// timing leaks nothing about the tag.
	expect := cbcTag(dec.preset.Hash, macKey, aadBytes, segments.iv, segments.cipherText, dec.preset.TagLength)
	if !hmac.Equal(segments.tag, expect) {
		return nil, fmt.Errorf("%w: %w: auth tag check failed", jwt.ErrTokenRejected, ErrInvalidSecret)
	}

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, fmt.Errorf("new cipher: %w", err)
	}

	// The decoded ciphertext belongs to this call, so CBC decrypts it in place.
	cipher.NewCBCDecrypter(block, segments.iv).CryptBlocks(segments.cipherText, segments.cipherText)

	plainText, err := internal.PKCS7UnPadding(segments.cipherText)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidToken, err)
	}

	return plainText, nil
}

// cbcTag computes the AES_CBC_HMAC_SHA2 authentication tag of RFC 7518 §5.2.2.1. The tag is the
// HMAC of the additional authenticated data, the IV, the ciphertext and AL, in that order. The HMAC
// is keyed with macKey and truncated to tagLength octets. AL is the bit length of the additional
// authenticated data, as a big-endian uint64.
func cbcTag(hash crypto.Hash, macKey, aadBytes, iv, cipherText []byte, tagLength int) []byte {
	al := make([]byte, 8)
	binary.BigEndian.PutUint64(al, uint64(len(aadBytes)*8))

	mac := hmac.New(hash.New, macKey)
	mac.Write(aadBytes)
	mac.Write(iv)
	mac.Write(cipherText)
	mac.Write(al)

	return mac.Sum(nil)[:tagLength]
}
