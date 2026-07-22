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

// AESCBCPreset holds the parameters of one AES_CBC_HMAC_SHA2 variant: the enc
// identifier, the HMAC hash, and the key and tag lengths. Use one of the package
// presets.
type AESCBCPreset struct {
	Enc       jwa.Enc
	Hash      crypto.Hash
	KeyLen    int
	EncKeyLen int
	MACKeyLen int
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

// AESCBCEncryptionConfig configures NewAESCBCEncryption. CEKManager supplies the
// content encryption key; AdditionalData, when set, is authenticated but not encrypted.
type AESCBCEncryptionConfig struct {
	CEKManager     CEKManager
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
func NewAESCBCEncryption(config *AESCBCEncryptionConfig, presets AESCBCPreset) *AESCBCEncryption {
	return &AESCBCEncryption{
		cekManager:     config.CEKManager,
		additionalData: config.AdditionalData,
		enc:            presets.Enc,
		hash:           presets.Hash,
		keyLength:      presets.EncKeyLen,
		macKeyLength:   presets.MACKeyLen,
		tagLength:      presets.TagLength,
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

	// A CEKManager may pin the token to a specific enc; honor that pin.
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

	// A fresh random 128-bit IV, unique per encryption.
	iv := make([]byte, 16)

	_, err = rand.Read(iv)
	if err != nil {
		return "", fmt.Errorf("(AESCBCEncryption.Transform) generate IV: %w", err)
	}

	// K splits into two subkeys: MAC_KEY is its leading octets, ENC_KEY its trailing
	// octets. The MAC key comes first, the reverse of the order the name suggests in
	// "AES_CBC_HMAC_SHA2".
	encKey := secret[enc.keyLength:]
	macKey := secret[:enc.macKeyLength]

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return "", fmt.Errorf("(AESCBCEncryption.Transform) new cipher: %w", err)
	}

	blockMode := cipher.NewCBCEncrypter(block, iv)
	origData := internal.PKCS7Padding(plainText, block.BlockSize())
	cipherText := make([]byte, len(origData))
	blockMode.CryptBlocks(cipherText, origData)

	// AAD binds the encoded protected header (RFC 7516 §5.1) plus any application data. AL is its
	// length in bits as a big-endian uint64, the last input to the tag.
	aadBytes := aad(token.Header, enc.additionalData)

	al := make([]byte, 8)
	binary.BigEndian.PutUint64(al, uint64(len(aadBytes)*8))

	// The tag is HMAC over AAD, IV, ciphertext, and AL in the order the spec fixes, truncated to
	// tagLength octets.
	authenticationTag := hmac.New(enc.hash.New, macKey)
	authenticationTag.Write(aadBytes)
	authenticationTag.Write(iv)
	authenticationTag.Write(cipherText)
	authenticationTag.Write(al)

	var encodedSecret string
	if len(encryptedSecret) > 0 {
		encodedSecret = base64.RawURLEncoding.EncodeToString(encryptedSecret)
	}

	return jwt.EncryptedToken{
		Header:     token.Header,
		EncKey:     encodedSecret,
		IV:         base64.RawURLEncoding.EncodeToString(iv),
		CipherText: base64.RawURLEncoding.EncodeToString(cipherText),
		Tag:        base64.RawURLEncoding.EncodeToString(authenticationTag.Sum(nil)[:enc.tagLength]),
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

// AESCBCDecryptionConfig configures NewAESCBCDecryption. CEKDecoder recovers the
// content encryption key; AdditionalData must equal the value used at encryption.
type AESCBCDecryptionConfig struct {
	CEKDecoder     CEKDecoder
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
func NewAESCBCDecryption(config *AESCBCDecryptionConfig, presets AESCBCPreset) *AESCBCDecryption {
	return &AESCBCDecryption{
		cekDecoder:     config.CEKDecoder,
		additionalData: config.AdditionalData,
		enc:            presets.Enc,
		hash:           presets.Hash,
		keyLength:      presets.EncKeyLen,
		macKeyLength:   presets.MACKeyLen,
		tagLength:      presets.TagLength,
	}
}

func (dec *AESCBCDecryption) Transform(ctx context.Context, header *jwa.JWH, rawToken string) ([]byte, error) {
	if header.Enc != dec.enc {
		return nil, fmt.Errorf(
			"(AESCBCDecryption.Transform) %w: invalid enc %s, expected %s",
			jwt.ErrMismatchRecipientPlugin, header.Enc, dec.enc,
		)
	}

	token, err := jwt.DecodeToken(rawToken, &jwt.EncryptedTokenDecoder{})
	if err != nil {
		return nil, fmt.Errorf("(AESCBCDecryption.Transform) split token: %w", err)
	}

	var encryptedKey []byte
	if len(token.EncKey) > 0 {
		encryptedKey, err = base64.RawURLEncoding.DecodeString(token.EncKey)
	}

	if err != nil {
		return nil, fmt.Errorf("(AESCBCDecryption.Transform) decode enc key: %w", err)
	}

	iv, err := base64.RawURLEncoding.DecodeString(token.IV)
	if err != nil {
		return nil, fmt.Errorf("(AESCBCDecryption.Transform) decode iv: %w", err)
	}

	tag, err := base64.RawURLEncoding.DecodeString(token.Tag)
	if err != nil {
		return nil, fmt.Errorf("(AESCBCDecryption.Transform) decode tag: %w", err)
	}

	cipherText, err := base64.RawURLEncoding.DecodeString(token.CipherText)
	if err != nil {
		return nil, fmt.Errorf("(AESCBCDecryption.Transform) decode cipher text: %w", err)
	}

	cek, err := dec.cekDecoder.ComputeCEK(ctx, header, encryptedKey)
	if err != nil {
		return nil, fmt.Errorf("(AESCBCDecryption.Transform) get secret key: %w", err)
	}

	if len(cek) != dec.keyLength+dec.macKeyLength {
		return nil, fmt.Errorf(
			"(AESCBCDecryption.Transform) %w: cek has length %d, expected %d",
			ErrInvalidSecret, len(cek), dec.keyLength+dec.macKeyLength,
		)
	}

	// K splits into two subkeys: MAC_KEY is its leading octets, ENC_KEY its trailing
	// octets. The MAC key comes first, the reverse of the order the name suggests in
	// "AES_CBC_HMAC_SHA2".
	encKey := cek[dec.keyLength:]
	macKey := cek[:dec.macKeyLength]

	// Recompute the tag over the same inputs as encryption — including the encoded protected header
	// as AAD — and reject the token unless it matches, before touching the ciphertext. hmac.Equal
	// compares in constant time to avoid leaking the tag through timing.
	aadBytes := aad(token.Header, dec.additionalData)

	al := make([]byte, 8)
	binary.BigEndian.PutUint64(al, uint64(len(aadBytes)*8))

	mac := hmac.New(dec.hash.New, macKey)
	mac.Write(aadBytes)
	mac.Write(iv)
	mac.Write(cipherText)
	mac.Write(al)

	expect := mac.Sum(nil)[:dec.tagLength]
	if !hmac.Equal(tag, expect) {
		return nil, fmt.Errorf("(AESCBCDecryption.Transform) %w: auth tag check failed", ErrInvalidSecret)
	}

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, fmt.Errorf("(AESCBCDecryption.Transform) new cipher: %w", err)
	}

	blockMode := cipher.NewCBCDecrypter(block, iv)
	origData := make([]byte, len(cipherText))
	blockMode.CryptBlocks(origData, cipherText)

	plainText, err := internal.PKCS7UnPadding(origData)
	if err != nil {
		return nil, fmt.Errorf("(AESCBCDecryption.Transform) %w: %w", ErrInvalidToken, err)
	}

	return plainText, nil
}
