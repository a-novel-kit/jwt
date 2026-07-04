package jwek

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec
	"crypto/sha256"
	"fmt"
	"hash"

	"github.com/a-novel-kit/jwt"
	"github.com/a-novel-kit/jwt/jwa"
)

// RSAOAEPKeyEncPreset pairs a JWA algorithm identifier with the hash used by
// RSAES-OAEP. Use one of the predefined presets rather than building one by hand.
type RSAOAEPKeyEncPreset struct {
	Alg  jwa.Alg
	Hash hash.Hash
}

var (
	// Deprecated: this preset uses the broken SHA-1 hash function. Use RSAOAEP256 instead.
	RSAOAEP = RSAOAEPKeyEncPreset{
		Alg:  jwa.RSAOAEP,
		Hash: sha1.New(), //nolint:gosec
	}
	RSAOAEP256 = RSAOAEPKeyEncPreset{
		Alg:  jwa.RSAOAEP256,
		Hash: sha256.New(),
	}
)

// RSAOAEPKeyEncManagerConfig holds the content encryption key to protect and the
// recipient RSA public key that encrypts it.
type RSAOAEPKeyEncManagerConfig struct {
	CEK    []byte
	EncKey *rsa.PublicKey
}

// RSAOAEPKeyEncManager implements jwe.CEKManager, encrypting the content encryption
// key to the recipient with RSAES-OAEP. See RFC 7518 section 4.3.
type RSAOAEPKeyEncManager struct {
	cek    []byte
	encKey *rsa.PublicKey

	alg  jwa.Alg
	hash hash.Hash
}

// NewRSAOAEPKeyEncManager creates a jwe.CEKManager that encrypts the content
// encryption key to the recipient with RSAES-OAEP. The preset selects the
// algorithm and hash; use RSAOAEP256 (RSAOAEP is deprecated, see its note).
//
// https://datatracker.ietf.org/doc/html/rfc7518#section-4.3
func NewRSAOAEPKeyEncManager(
	config *RSAOAEPKeyEncManagerConfig, preset RSAOAEPKeyEncPreset,
) *RSAOAEPKeyEncManager {
	return &RSAOAEPKeyEncManager{
		cek:    config.CEK,
		encKey: config.EncKey,
		alg:    preset.Alg,
		hash:   preset.Hash,
	}
}

func (manager *RSAOAEPKeyEncManager) SetHeader(_ context.Context, header *jwa.JWH) (*jwa.JWH, error) {
	if !header.Alg.Empty() {
		return nil, fmt.Errorf(
			"(RSAOAEPKeyEncManager.SetHeader) %w: alg field already set",
			jwt.ErrConflictingHeader,
		)
	}

	header.Alg = manager.alg

	return header, nil
}

func (manager *RSAOAEPKeyEncManager) ComputeCEK(_ context.Context, _ *jwa.JWH) ([]byte, error) {
	return manager.cek, nil
}

func (manager *RSAOAEPKeyEncManager) EncryptCEK(_ context.Context, _ *jwa.JWH, cek []byte) ([]byte, error) {
	encoded, err := rsa.EncryptOAEP(manager.hash, rand.Reader, manager.encKey, cek, nil)
	if err != nil {
		return nil, fmt.Errorf("(RSAOAEPKeyEncManager.EncryptCEK) encrypt: %w", err)
	}

	return encoded, nil
}

// RSAOAEPKeyEncDecoderConfig holds the recipient RSA private key used to decrypt
// the content encryption key.
type RSAOAEPKeyEncDecoderConfig struct {
	EncKey *rsa.PrivateKey
}

// RSAOAEPKeyEncDecoder implements jwe.CEKDecoder, decrypting a content encryption
// key that was encrypted with RSAES-OAEP. See RFC 7518 section 4.3.
type RSAOAEPKeyEncDecoder struct {
	encKey *rsa.PrivateKey

	alg  jwa.Alg
	hash hash.Hash
}

// NewRSAOAEPKeyEncDecoder creates a jwe.CEKDecoder that decrypts an RSAES-OAEP
// encrypted content encryption key. The preset must match the one used to encrypt
// the token; use RSAOAEP256 (RSAOAEP is deprecated, see its note).
//
// https://datatracker.ietf.org/doc/html/rfc7518#section-4.3
func NewRSAOAEPKeyEncDecoder(
	config *RSAOAEPKeyEncDecoderConfig, preset RSAOAEPKeyEncPreset,
) *RSAOAEPKeyEncDecoder {
	return &RSAOAEPKeyEncDecoder{
		encKey: config.EncKey,
		alg:    preset.Alg,
		hash:   preset.Hash,
	}
}

func (decoder *RSAOAEPKeyEncDecoder) ComputeCEK(_ context.Context, header *jwa.JWH, encKey []byte) ([]byte, error) {
	if header.Alg != decoder.alg {
		return nil, fmt.Errorf(
			"(RSAOAEPKeyEncDecoder.ComputeCEK) %w: invalid algorithm %s, expected %s",
			jwt.ErrMismatchRecipientPlugin, header.Alg, decoder.alg,
		)
	}

	if len(encKey) == 0 {
		return nil, fmt.Errorf(
			"(RSAOAEPKeyEncDecoder.ComputeCEK) %w: missing enc key",
			jwt.ErrUnsupportedTokenFormat,
		)
	}

	cek, err := rsa.DecryptOAEP(decoder.hash, rand.Reader, decoder.encKey, encKey, nil)
	if err != nil {
		return nil, fmt.Errorf("(RSAOAEPKeyEncDecoder.ComputeCEK) decrypt: %w", err)
	}

	return cek, nil
}
