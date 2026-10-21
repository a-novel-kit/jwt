package jwe

import (
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
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
	cekManager     CEKManager
	additionalData []byte

	enc          jwa.Enc
	hash         crypto.Hash
	keyLength    int
	macKeyLength int
	tagLength    int
}

// NewAESCBCEncryption creates a jwt.ProducerPlugin that encrypts a token payload
// with AES_CBC_HMAC_SHA2. Pass one of the package's AESCBCPreset values to select
// the variant.
//
// https://datatracker.ietf.org/doc/html/rfc7518#section-5.2
func NewAESCBCEncryption(config *AESCBCEncryptionConfig, preset AESCBCPreset) *AESCBCEncryption {
	return &AESCBCEncryption{
		cekManager:     config.CEKManager,
		additionalData: config.AdditionalData,
		enc:            preset.Enc,
		hash:           preset.Hash,
		keyLength:      preset.EncKeyLen,
		macKeyLength:   preset.MACKeyLen,
		tagLength:      preset.TagLength,
	}
}

func (enc *AESCBCEncryption) Header(ctx context.Context, header *jwa.JWH) (*jwa.JWH, error) {
	if header.Enc != "" {
		return nil, fmt.Errorf("(AESCBCEncryption.Header) %w: enc field already set", jwt.ErrConflictingHeader)
	}

	var err error

	header, err = enc.cekManager.SetHeader(ctx, header)
	if err != nil {
		return nil, fmt.Errorf("(AESCBCEncryption.Header) set key derivation header: %w", err)
	}

	// A CEKManager may pin the token to one enc, which this plugin must then match.
	if header.Enc != "" && header.Enc != enc.enc {
		return nil, fmt.Errorf(
			"(AESCBCEncryption.Header) %w: cek manager is incompatible with the current encryption algorithm: "+
				"expected %s, got %s",
			jwt.ErrConflictingHeader, enc.enc, header.Enc,
		)
	}

	header.Enc = enc.enc

	return header, nil
}

func (enc *AESCBCEncryption) Transform(ctx context.Context, header *jwa.JWH, rawToken string) (string, error) {
	token, err := jwt.DecodeToken(rawToken, &jwt.RawTokenDecoder{})
	if err != nil {
		return "", fmt.Errorf("(AESCBCEncryption.Transform) split token: %w", err)
	}

	plainText, err := base64.RawURLEncoding.DecodeString(token.Payload)
	if err != nil {
		return "", fmt.Errorf("(AESCBCEncryption.Transform) decode payload: %w", err)
	}

	secret, err := enc.getCEK(ctx, header)
	if err != nil {
		return "", fmt.Errorf("(AESCBCEncryption.Transform) get secret key: %w", err)
	}

	encryptedSecret, err := enc.cekManager.EncryptCEK(ctx, header, secret)
	if err != nil {
		return "", fmt.Errorf("(AESCBCEncryption.Transform) encrypt key: %w", err)
	}

	encodedHeader, err := encodeProtectedHeader(header)
	if err != nil {
		return "", fmt.Errorf("(AESCBCEncryption.Transform) %w", err)
	}

	// A fresh random 128-bit IV, unique per encryption.
	iv := make([]byte, 16)

	_, err = rand.Read(iv)
	if err != nil {
		return "", fmt.Errorf("(AESCBCEncryption.Transform) generate IV: %w", err)
	}

	// K splits into two subkeys: MAC_KEY is its leading octets, ENC_KEY its trailing
	// octets. The MAC key comes first, the reverse of the order the name suggests in
	// "AES_CBC_HMAC_SHA2".
	encKey := secret[enc.macKeyLength:]
	macKey := secret[:enc.macKeyLength]

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return "", fmt.Errorf("(AESCBCEncryption.Transform) new cipher: %w", err)
	}

	blockMode := cipher.NewCBCEncrypter(block, iv)
	origData := internal.PKCS7Padding(plainText, block.BlockSize())
	cipherText := make([]byte, len(origData))
	blockMode.CryptBlocks(cipherText, origData)

	aadBytes := aad(encodedHeader, enc.additionalData)
	tag := cbcTag(enc.hash, macKey, aadBytes, iv, cipherText, enc.tagLength)

	return jwt.EncryptedToken{
		Header:     encodedHeader,
		EncKey:     base64.RawURLEncoding.EncodeToString(encryptedSecret),
		IV:         base64.RawURLEncoding.EncodeToString(iv),
		CipherText: base64.RawURLEncoding.EncodeToString(cipherText),
		Tag:        base64.RawURLEncoding.EncodeToString(tag),
	}.String(), nil
}

func (enc *AESCBCEncryption) getCEK(ctx context.Context, header *jwa.JWH) ([]byte, error) {
	secret, err := enc.cekManager.ComputeCEK(ctx, header)
	if err != nil {
		return nil, fmt.Errorf("(AESCBCEncryption.getCEK) compute cek: %w", err)
	}

	if len(secret) != enc.keyLength+enc.macKeyLength {
		return nil, fmt.Errorf(
			"(AESCBCEncryption.getCEK) %w: cek has length %d, expected %d",
			ErrInvalidSecret, len(secret), enc.keyLength+enc.macKeyLength,
		)
	}

	return secret, nil
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
	cekDecoder     CEKDecoder
	additionalData []byte

	enc          jwa.Enc
	hash         crypto.Hash
	keyLength    int
	macKeyLength int
	tagLength    int
}

// NewAESCBCDecryption creates a jwt.RecipientPlugin that decrypts a token encrypted
// with AES_CBC_HMAC_SHA2. Pass one of the package's AESCBCPreset values to select the
// variant; it must match the one used at encryption.
//
// https://datatracker.ietf.org/doc/html/rfc7518#section-5.2
func NewAESCBCDecryption(config *AESCBCDecryptionConfig, preset AESCBCPreset) *AESCBCDecryption {
	return &AESCBCDecryption{
		cekDecoder:     config.CEKDecoder,
		additionalData: config.AdditionalData,
		enc:            preset.Enc,
		hash:           preset.Hash,
		keyLength:      preset.EncKeyLen,
		macKeyLength:   preset.MACKeyLen,
		tagLength:      preset.TagLength,
	}
}

func (dec *AESCBCDecryption) Transform(ctx context.Context, header *jwa.JWH, rawToken string) ([]byte, error) {
	if header.Enc != dec.enc {
		return nil, fmt.Errorf(
			"(AESCBCDecryption.Transform) %w: invalid enc %s, expected %s",
			jwt.ErrMismatchRecipientPlugin, header.Enc, dec.enc,
		)
	}

	// This package performs no decompression, so it refuses a compressed payload.
	if header.Zip != "" {
		return nil, fmt.Errorf(
			"(AESCBCDecryption.Transform) %w: unsupported zip %s", jwt.ErrUnsupportedTokenFormat, header.Zip,
		)
	}

	token, err := jwt.DecodeToken(rawToken, &jwt.EncryptedTokenDecoder{})
	if err != nil {
		return nil, fmt.Errorf("(AESCBCDecryption.Transform) split token: %w", err)
	}

	segments, err := decodeSegments(token)
	if err != nil {
		return nil, fmt.Errorf("(AESCBCDecryption.Transform) %w", err)
	}

	cek, err := dec.cekDecoder.ComputeCEK(ctx, header, segments.encryptedKey)
	if err != nil {
		return nil, fmt.Errorf("(AESCBCDecryption.Transform) get secret key: %w", err)
	}

	if len(cek) != dec.keyLength+dec.macKeyLength {
		return nil, fmt.Errorf(
			"(AESCBCDecryption.Transform) %w: cek has length %d, expected %d",
			ErrInvalidSecret, len(cek), dec.keyLength+dec.macKeyLength,
		)
	}

	// The IV and ciphertext are attacker-supplied, and the CBC decrypter panics unless the IV is one
	// block and the ciphertext whole blocks. A sender who knows the CEK passes the tag check with
	// either, so the lengths are checked first.
	if len(segments.iv) != aes.BlockSize {
		return nil, fmt.Errorf(
			"(AESCBCDecryption.Transform) %w: iv length %d, expected %d",
			ErrInvalidToken, len(segments.iv), aes.BlockSize,
		)
	}

	if len(segments.cipherText)%aes.BlockSize != 0 {
		return nil, fmt.Errorf(
			"(AESCBCDecryption.Transform) %w: cipher text length %d is not a multiple of %d",
			ErrInvalidToken, len(segments.cipherText), aes.BlockSize,
		)
	}

	// MAC_KEY leads K and ENC_KEY trails it, as at encryption.
	encKey := cek[dec.macKeyLength:]
	macKey := cek[:dec.macKeyLength]

	// The tag is checked before the ciphertext is touched. hmac.Equal compares in constant time, so
	// timing leaks nothing about the tag.
	aadBytes := aad(token.Header, dec.additionalData)

	expect := cbcTag(dec.hash, macKey, aadBytes, segments.iv, segments.cipherText, dec.tagLength)
	if !hmac.Equal(segments.tag, expect) {
		return nil, fmt.Errorf("(AESCBCDecryption.Transform) %w: auth tag check failed", ErrInvalidSecret)
	}

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, fmt.Errorf("(AESCBCDecryption.Transform) new cipher: %w", err)
	}

	blockMode := cipher.NewCBCDecrypter(block, segments.iv)
	origData := make([]byte, len(segments.cipherText))
	blockMode.CryptBlocks(origData, segments.cipherText)

	plainText, err := internal.PKCS7UnPadding(origData)
	if err != nil {
		return nil, fmt.Errorf("(AESCBCDecryption.Transform) %w: %w", ErrInvalidToken, err)
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
