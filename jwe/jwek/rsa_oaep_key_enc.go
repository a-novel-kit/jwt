package jwek

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"

	"github.com/a-novel-kit/jwt/v2"
	"github.com/a-novel-kit/jwt/v2/jwa"
)

// RSAOAEPKeyEncPreset pairs a JWA algorithm identifier with the hash used by
// RSAES-OAEP, for both the label digest and MGF1. Use one of the predefined presets.
type RSAOAEPKeyEncPreset struct {
	Alg  jwa.Alg
	Hash crypto.Hash
}

var (
	// Deprecated: this preset uses the broken SHA-1 hash function. Use RSAOAEP256 instead.
	RSAOAEP = RSAOAEPKeyEncPreset{
		Alg:  jwa.RSAOAEP,
		Hash: crypto.SHA1,
	}
	RSAOAEP256 = RSAOAEPKeyEncPreset{
		Alg:  jwa.RSAOAEP256,
		Hash: crypto.SHA256,
	}
)

// RSAOAEPKeyEncManagerConfig holds the recipient RSA public key that encrypts each
// token's content encryption key.
type RSAOAEPKeyEncManagerConfig struct {
	// Deprecated: ignored. Each token is encrypted under a fresh random content encryption key, as
	// RFC 7516 requires.
	CEK    []byte
	EncKey *rsa.PublicKey
}

// RSAOAEPKeyEncManager implements jwe.CEKManager, encrypting the content encryption
// key to the recipient with RSAES-OAEP. See RFC 7518 section 4.3.
type RSAOAEPKeyEncManager struct {
	encKey *rsa.PublicKey

	alg  jwa.Alg
	hash crypto.Hash
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

func (manager *RSAOAEPKeyEncManager) ComputeCEK(_ context.Context, header *jwa.JWH) ([]byte, error) {
	cek, err := newCEK(header)
	if err != nil {
		return nil, fmt.Errorf("(RSAOAEPKeyEncManager.ComputeCEK) %w", err)
	}

	return cek, nil
}

func (manager *RSAOAEPKeyEncManager) EncryptCEK(_ context.Context, _ *jwa.JWH, cek []byte) ([]byte, error) {
	encoded, err := rsa.EncryptOAEPWithOptions(rand.Reader, manager.encKey, cek, &rsa.OAEPOptions{Hash: manager.hash})
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
	hash crypto.Hash
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

	cek, err := decoder.encKey.Decrypt(nil, encKey, &rsa.OAEPOptions{Hash: decoder.hash})
	if err != nil {
		return nil, fmt.Errorf("(RSAOAEPKeyEncDecoder.ComputeCEK) decrypt: %w", err)
	}

	return cek, nil
}
