package jwek

import (
	"context"
	"crypto/aes"
	"crypto/ecdh"
	"encoding/base64"
	"fmt"

	"github.com/a-novel-kit/jwt/v2"
	"github.com/a-novel-kit/jwt/v2/jwa"
	"github.com/a-novel-kit/jwt/v2/jwe/internal"
)

var (
	// ECDHESA128KW derives a 16-byte key-wrapping key with ECDH-ES, then wraps the content encryption
	// key with AES Key Wrap.
	ECDHESA128KW = KeyWrapPreset{
		Alg:    jwa.ECDHESA128KW,
		KeyLen: 16,
	}
	// ECDHESA192KW derives a 24-byte key-wrapping key with ECDH-ES, then wraps the content encryption
	// key with AES Key Wrap.
	ECDHESA192KW = KeyWrapPreset{
		Alg:    jwa.ECDHESA192KW,
		KeyLen: 24,
	}
	// ECDHESA256KW derives a 32-byte key-wrapping key with ECDH-ES, then wraps the content encryption
	// key with AES Key Wrap.
	ECDHESA256KW = KeyWrapPreset{
		Alg:    jwa.ECDHESA256KW,
		KeyLen: 32,
	}
)

// ECDHKeyAgrKWManagerConfig configures NewECDHKeyAgrKWManager.
type ECDHKeyAgrKWManagerConfig struct {
	// Deprecated: ignored. Each token agrees on its key with a fresh ephemeral key pair, as
	// ECDH-ES requires.
	ProducerKey *ecdh.PrivateKey
	// RecipientKey is the recipient's static public key, one half of the Diffie-Hellman exchange.
	RecipientKey *ecdh.PublicKey

	// Deprecated: ignored. Each token is encrypted under a fresh random content encryption key, as
	// RFC 7516 requires.
	CEK []byte

	// ProducerInfo is the optional PartyUInfo mixed into the key derivation and published as "apu".
	ProducerInfo string
	// RecipientInfo is the optional PartyVInfo mixed into the key derivation and published as "apv".
	RecipientInfo string
}

// ECDHKeyAgrKWManager implements jwe.CEKManager: it derives a key-wrapping key with
// ECDH-ES and then wraps the content encryption key with AES Key Wrap. Each token
// draws a fresh content encryption key and a fresh ephemeral key pair, whose public
// half it publishes in the "epk" header.
type ECDHKeyAgrKWManager struct {
	config ECDHKeyAgrKWManagerConfig

	alg    jwa.Alg
	keyLen int
}

// NewECDHKeyAgrKWManager creates a jwe.CEKManager that derives a key-wrapping key
// with ECDH-ES (Concat KDF) and wraps the content encryption key with AES Key Wrap.
// The preset selects the algorithm and wrap-key length; use one of the
// KeyWrapPreset values (for example ECDHESA128KW).
//
// https://datatracker.ietf.org/doc/html/rfc7518#section-4.6
func NewECDHKeyAgrKWManager(
	config *ECDHKeyAgrKWManagerConfig, preset KeyWrapPreset,
) *ECDHKeyAgrKWManager {
	return &ECDHKeyAgrKWManager{
		config: *config,
		alg:    preset.Alg,
		keyLen: preset.KeyLen,
	}
}

func (manager *ECDHKeyAgrKWManager) SetHeader(_ context.Context, header *jwa.JWH) (*jwa.JWH, error) {
	if !header.Alg.Empty() {
		return nil, fmt.Errorf("(ECDHKeyAgrKWManager.SetHeader) %w: alg field already set", jwt.ErrConflictingHeader)
	}

	header.JWHKeyAgreement = jwa.JWHKeyAgreement{
		APU: base64.RawURLEncoding.EncodeToString([]byte(manager.config.ProducerInfo)),
		APV: base64.RawURLEncoding.EncodeToString([]byte(manager.config.RecipientInfo)),
	}
	header.Alg = manager.alg

	return header, nil
}

func (manager *ECDHKeyAgrKWManager) ComputeCEK(_ context.Context, header *jwa.JWH) ([]byte, error) {
	cek, err := newCEK(header)
	if err != nil {
		return nil, fmt.Errorf("(ECDHKeyAgrKWManager.ComputeCEK) %w", err)
	}

	return cek, nil
}

func (manager *ECDHKeyAgrKWManager) EncryptCEK(_ context.Context, header *jwa.JWH, cek []byte) ([]byte, error) {
	z, err := ephemeralAgreement(header, manager.config.RecipientKey)
	if err != nil {
		return nil, fmt.Errorf("(ECDHKeyAgrKWManager.EncryptCEK) %w", err)
	}

	apu, apv, err := agreementInfo(header)
	if err != nil {
		return nil, fmt.Errorf("(ECDHKeyAgrKWManager.EncryptCEK) %w", err)
	}

	wrapKey, err := internal.Derive(z, string(manager.alg), manager.keyLen, apu, apv)
	if err != nil {
		return nil, fmt.Errorf("(ECDHKeyAgrKWManager.EncryptCEK) derive key: %w", err)
	}

	block, err := aes.NewCipher(wrapKey)
	if err != nil {
		return nil, fmt.Errorf("(ECDHKeyAgrKWManager.EncryptCEK) create cipher: %w", err)
	}

	wrapped, err := internal.KeyWrap(block, cek)
	if err != nil {
		return nil, fmt.Errorf("(ECDHKeyAgrKWManager.EncryptCEK) wrap key: %w", err)
	}

	return wrapped, nil
}

// ECDHKeyAgrKWDecoderConfig configures NewECDHKeyAgrKWDecoder.
type ECDHKeyAgrKWDecoderConfig struct {
	// RecipientKey is the recipient's private key, which agrees on the shared secret with the
	// ephemeral public key the token header carries.
	RecipientKey *ecdh.PrivateKey
}

// ECDHKeyAgrKWDecoder implements jwe.CEKDecoder: it re-derives the key-wrapping key
// with ECDH-ES and unwraps the content encryption key with AES Key Wrap.
type ECDHKeyAgrKWDecoder struct {
	config ECDHKeyAgrKWDecoderConfig

	alg    jwa.Alg
	keyLen int
}

// NewECDHKeyAgrKWDecoder creates a jwe.CEKDecoder that re-derives the key-wrapping
// key with ECDH-ES (Concat KDF) and unwraps the content encryption key with AES Key
// Wrap. The preset must match the one used to encrypt the token; use one of the
// KeyWrapPreset values (for example ECDHESA128KW).
//
// https://datatracker.ietf.org/doc/html/rfc7518#section-4.6
func NewECDHKeyAgrKWDecoder(config *ECDHKeyAgrKWDecoderConfig, preset KeyWrapPreset) *ECDHKeyAgrKWDecoder {
	return &ECDHKeyAgrKWDecoder{
		config: *config,
		alg:    preset.Alg,
		keyLen: preset.KeyLen,
	}
}

func (decoder *ECDHKeyAgrKWDecoder) ComputeCEK(_ context.Context, header *jwa.JWH, encKey []byte) ([]byte, error) {
	if header.Alg != decoder.alg {
		return nil, fmt.Errorf(
			"(ECDHKeyAgrKWDecoder.ComputeCEK) %w: invalid algorithm %s, expected %s",
			jwt.ErrMismatchRecipientPlugin, header.Alg, decoder.alg,
		)
	}

	if len(encKey) == 0 {
		return nil, fmt.Errorf(
			"(ECDHKeyAgrKWDecoder.ComputeCEK) %w: missing enc key",
			jwt.ErrUnsupportedTokenFormat,
		)
	}

	z, err := recipientAgreement(header, decoder.config.RecipientKey)
	if err != nil {
		return nil, fmt.Errorf("(ECDHKeyAgrKWDecoder.ComputeCEK) %w", err)
	}

	apu, apv, err := agreementInfo(header)
	if err != nil {
		return nil, fmt.Errorf("(ECDHKeyAgrKWDecoder.ComputeCEK) %w: %w", jwt.ErrUnsupportedTokenFormat, err)
	}

	kek, err := internal.Derive(z, string(decoder.alg), decoder.keyLen, apu, apv)
	if err != nil {
		return nil, fmt.Errorf("(ECDHKeyAgrKWDecoder.ComputeCEK) derive key: %w", err)
	}

	if len(kek) != decoder.keyLen {
		return nil, fmt.Errorf(
			"(ECDHKeyAgrKWDecoder.ComputeCEK) %w: derived key length is %d, expected %d",
			jwt.ErrUnsupportedTokenFormat, len(kek), decoder.keyLen,
		)
	}

	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("(ECDHKeyAgrKWDecoder.ComputeCEK) create cipher: %w", err)
	}

	cek, err := internal.KeyUnwrap(block, encKey)
	if err != nil {
		return nil, fmt.Errorf("(ECDHKeyAgrKWDecoder.ComputeCEK) %w: unwrap key: %w", jwt.ErrTokenRejected, err)
	}

	return cek, nil
}
