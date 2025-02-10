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

	"github.com/a-novel-kit/jwt"
	"github.com/a-novel-kit/jwt/jwa"
	"github.com/a-novel-kit/jwt/jwe/internal"
)

type AESCBCPreset struct {
	Enc       jwa.Enc
	Hash      crypto.Hash
	KeyLen    int
	EncKeyLen int
	MACKeyLen int
	TagLength int
}

var (
	A128CBCHS256 = AESCBCPreset{
		Enc:       jwa.A128CBC,
		Hash:      crypto.SHA256,
		KeyLen:    32,
		EncKeyLen: 16,
		MACKeyLen: 16,
		TagLength: 16,
	}
	A192CBCHS384 = AESCBCPreset{
		Enc:       jwa.A192CBC,
		Hash:      crypto.SHA384,
		KeyLen:    48,
		EncKeyLen: 24,
		MACKeyLen: 24,
		TagLength: 24,
	}
	A256CBCHS512 = AESCBCPreset{
		Enc:       jwa.A256CBC,
		Hash:      crypto.SHA512,
		KeyLen:    64,
		EncKeyLen: 32,
		MACKeyLen: 32,
		TagLength: 32,
	}
)

type AESCBCEncryptionConfig struct {
	CEKManager     CEKManager
	AdditionalData []byte
}

type AESCBCEncryption struct {
	cekManager     CEKManager
	additionalData []byte

	enc          jwa.Enc
	hash         crypto.Hash
	keyLength    int
	macKeyLength int
	tagLength    int
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

func (enc *AESCBCEncryption) Header(ctx context.Context, header *jwa.JWH) (*jwa.JWH, error) {
	if header.Enc != "" {
		return nil, fmt.Errorf("(AESCBCEncryption.Header) %w: enc field already set", jwt.ErrConflictingHeader)
	}

	var err error

	header, err = enc.cekManager.SetHeader(ctx, header)
	if err != nil {
		return nil, fmt.Errorf("(AESCBCEncryption.Header) set key derivation header: %w", err)
	}

	// If the CEK CEKManager specifies an explicit enc compatibility, it must be respected.
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

	// The IV used is a 128-bit value generated randomly or pseudorandomly for use in the cipher.
	iv := make([]byte, 16)
	if _, err := rand.Read(iv); err != nil {
		return "", fmt.Errorf("(AESCBCEncryption.Transform) generate IV: %w", err)
	}

	// The secondary keys MAC_KEY and ENC_KEY are generated from the
	// input key K as follows. Each of these two keys is an octet
	// string.
	//
	// - MAC_KEY consists of the initial MAC_KEY_LEN octets of K, in order.
	// - ENC_KEY consists of the final ENC_KEY_LEN octets of K, in order.
	//
	// The number of octets in the input key K MUST be the sum of
	// MAC_KEY_LEN and ENC_KEY_LEN. The values of these parameters are
	// specified by the Authenticated Encryption algorithms in Sections
	// 5.2.3 through 5.2.5. Note that the MAC key comes before the
	// encryption key in the input key K; this is in the opposite order
	// of the algorithm names in the identifier "AES_CBC_HMAC_SHA2".
	encKey := secret[enc.keyLength:]
	macKey := secret[:enc.macKeyLength]

	// The plaintext is CBC encrypted using PKCS #7 padding using
	// ENC_KEY as the key and the IV.
	block, err := aes.NewCipher(encKey) // New cipher with ENC_KEY
	if err != nil {
		return "", fmt.Errorf("(AESCBCEncryption.Transform) new cipher: %w", err)
	}

	blockMode := cipher.NewCBCEncrypter(block, iv)
	// Pad the incoming data so it fits the block size.
	origData := internal.PKCS7Padding(plainText, block.BlockSize())
	// CipherText will hold the results of the encryption.
	cipherText := make([]byte, len(origData))
	blockMode.CryptBlocks(cipherText, origData)

	// The octet string AL is equal to the number of bits in the
	// Additional Authenticated Data A expressed as a 64-bit unsigned
	// big-endian integer.
	al := make([]byte, 8)
	binary.BigEndian.PutUint64(al, uint64(len(enc.additionalData)*8))

	// A message Authentication Tag T is computed by applying HMAC
	// [RFC2104] to the following data, in order:
	//
	// - the Additional Authenticated Data A,
	// - the Initialization Vector IV,
	// - the ciphertext E computed in the previous step, and
	// - the octet string AL defined above.
	//
	// The string MAC_KEY is used as the MAC key. We denote the output
	// of the MAC computed in this step as M. The first T_LEN octets of
	// M are used as T.
	authenticationTag := hmac.New(enc.hash.New, macKey)
	authenticationTag.Write(enc.additionalData)
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

// NewAESCBCEncryption creates a new jwt.ProducerPlugin for an encrypted token using AES_CBC_HMAC_SHA2.
//
// Use any of the AESCBCPreset constants to set the algorithm and hash function.
//   - A128CBCHS256: AES-128-CBC with HMAC-SHA-256
//   - A192CBCHS384: AES-192-CBC with HMAC-SHA-384
//   - A256CBCHS512: AES-256-CBC with HMAC-SHA-512
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

type AESCBCDecryptionConfig struct {
	CEKDecoder     CEKDecoder
	AdditionalData []byte
}

type AESCBCDecryption struct {
	cekDecoder     CEKDecoder
	additionalData []byte

	enc          jwa.Enc
	hash         crypto.Hash
	keyLength    int
	macKeyLength int
	tagLength    int
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

	// The secondary keys MAC_KEY and ENC_KEY are generated from the
	// input key K as follows. Each of these two keys is an octet
	// string.
	//
	// - MAC_KEY consists of the initial MAC_KEY_LEN octets of K, in order.
	// - ENC_KEY consists of the final ENC_KEY_LEN octets of K, in order.
	//
	// The number of octets in the input key K MUST be the sum of
	// MAC_KEY_LEN and ENC_KEY_LEN. The values of these parameters are
	// specified by the Authenticated Encryption algorithms in Sections
	// 5.2.3 through 5.2.5. Note that the MAC key comes before the
	// encryption key in the input key K; this is in the opposite order
	// of the algorithm names in the identifier "AES_CBC_HMAC_SHA2".
	encKey := cek[dec.keyLength:]
	macKey := cek[:dec.macKeyLength]

	// The integrity and authenticity of A and E are checked by
	// computing an HMAC with the inputs as in Step 5 of
	// Section 5.2.2.1.
	// The value T, from the previous step, is
	// compared to the first MAC_KEY length bits of the HMAC output.  If
	// those values are identical, then A and E are considered valid,
	// and processing is continued.  Otherwise, all of the data used in
	// the MAC validation are discarded, and the authenticated
	// decryption operation returns an indication that it failed, and
	// the operation halts.  (But see Section 11.5 of [JWE] for security
	// considerations on thwarting timing attacks.)
	al := make([]byte, 8)
	binary.BigEndian.PutUint64(al, uint64(len(dec.additionalData)*8))

	mac := hmac.New(dec.hash.New, macKey)
	mac.Write(dec.additionalData)
	mac.Write(iv)
	mac.Write(cipherText)
	mac.Write(al)

	expect := mac.Sum(nil)[:dec.tagLength]
	if !hmac.Equal(tag, expect) {
		return nil, fmt.Errorf("(AESCBCDecryption.Transform) %w: auth tag check failed", ErrInvalidSecret)
	}

	// The value E is decrypted and the PKCS #7 padding is checked and
	// removed. The value IV is used as the Initialization Vector. The
	// value ENC_KEY is used as the decryption key.
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, fmt.Errorf("(AESCBCDecryption.Transform) new cipher: %w", err)
	}

	blockMode := cipher.NewCBCDecrypter(block, iv)
	origData := make([]byte, len(cipherText))
	blockMode.CryptBlocks(origData, cipherText)

	return internal.PKCS7UnPadding(origData), nil
}

// NewAESCBCDecryption creates a new jwt.RecipientPlugin for a decrypted token using AES_CBC_HMAC_SHA2.
//
// Use any of the AESCBCPreset constants to set the algorithm and hash function.
//   - A128CBCHS256: AES-128-CBC with HMAC-SHA-256
//   - A192CBCHS384: AES-192-CBC with HMAC-SHA-384
//   - A256CBCHS512: AES-256-CBC with HMAC-SHA-512
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
