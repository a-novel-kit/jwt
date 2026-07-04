package jwek

import (
	"context"
	"crypto/aes"
	"crypto/ecdh"
	"encoding/json"
	"fmt"

	"golang.org/x/crypto/curve25519"

	"github.com/a-novel-kit/jwt"
	"github.com/a-novel-kit/jwt/jwa"
	"github.com/a-novel-kit/jwt/jwe/internal"
	"github.com/a-novel-kit/jwt/jwk/serializers"
)

// ECDHKeyAgrKWPreset pairs a JWA algorithm identifier with the length of the
// key-wrapping key derived from the shared secret. Use one of the predefined
// presets rather than building one by hand.
type ECDHKeyAgrKWPreset struct {
	Alg    jwa.Alg
	KeyLen int
}

// The ECDH-ES with AES Key Wrap presets, one per supported wrap-key length.
var (
	ECDHESA128KW = ECDHKeyAgrKWPreset{
		Alg:    jwa.ECDHESA128KW,
		KeyLen: 16,
	}
	ECDHESA192KW = ECDHKeyAgrKWPreset{
		Alg:    jwa.ECDHESA192KW,
		KeyLen: 24,
	}
	ECDHESA256KW = ECDHKeyAgrKWPreset{
		Alg:    jwa.ECDHESA256KW,
		KeyLen: 32,
	}
)

// ECDHKeyAgrKWManagerConfig holds the inputs for NewECDHKeyAgrKWManager.
// ProducerKey and RecipientKey are the two halves of the Diffie-Hellman exchange,
// CEK is the content encryption key to wrap, and ProducerInfo and RecipientInfo
// are the optional agreement party details mixed into the key derivation.
type ECDHKeyAgrKWManagerConfig struct {
	ProducerKey  *ecdh.PrivateKey
	RecipientKey *ecdh.PublicKey

	CEK []byte

	ProducerInfo  string
	RecipientInfo string
}

// ECDHKeyAgrKWManager implements jwe.CEKManager: it derives a key-wrapping key with
// ECDH-ES and then wraps the content encryption key with AES Key Wrap.
type ECDHKeyAgrKWManager struct {
	config ECDHKeyAgrKWManagerConfig

	alg    jwa.Alg
	keyLen int
}

// NewECDHKeyAgrKWManager creates a jwe.CEKManager that derives a key-wrapping key
// with ECDH-ES (Concat KDF) and wraps the content encryption key with AES Key Wrap.
// The preset selects the algorithm and wrap-key length; use one of the
// ECDHKeyAgrKWPreset values (for example ECDHESA128KW).
//
// https://datatracker.ietf.org/doc/html/rfc7518#section-4.6
func NewECDHKeyAgrKWManager(
	config *ECDHKeyAgrKWManagerConfig, preset ECDHKeyAgrKWPreset,
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

	// Publish the producer public key in the header: the recipient needs it to
	// derive the same shared secret from its own private key.
	publicKeyEncoded, err := serializers.EncodeECDH(manager.config.ProducerKey.PublicKey())
	if err != nil {
		return nil, fmt.Errorf("(ECDHKeyAgrKWManager.SetHeader) encode public key: %w", err)
	}

	publicKeySerialized, err := json.Marshal(publicKeyEncoded)
	if err != nil {
		return nil, fmt.Errorf("(ECDHKeyAgrKWManager.SetHeader) serialize shared public key: %w", err)
	}

	header.JWHKeyAgreement = jwa.JWHKeyAgreement{
		EPK: &jwa.JWK{Payload: publicKeySerialized},
		APU: manager.config.ProducerInfo,
		APV: manager.config.RecipientInfo,
	}
	header.Alg = manager.alg

	return header, nil
}

func (manager *ECDHKeyAgrKWManager) ComputeCEK(_ context.Context, _ *jwa.JWH) ([]byte, error) {
	return manager.config.CEK, nil
}

func (manager *ECDHKeyAgrKWManager) EncryptCEK(_ context.Context, header *jwa.JWH, cek []byte) ([]byte, error) {
	z, err := curve25519.X25519(manager.config.ProducerKey.Bytes(), manager.config.RecipientKey.Bytes())
	if err != nil {
		return nil, fmt.Errorf("(ECDHKeyAgrKWManager.EncryptCEK) derive shared secret: %w", err)
	}

	wrapKey, err := internal.Derive(z, string(manager.alg), manager.keyLen, header.APU, header.APV)
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

// ECDHKeyAgrKWDecoderConfig holds the recipient private key used to reconstruct the
// shared secret from the producer public key carried in the token header.
type ECDHKeyAgrKWDecoderConfig struct {
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
// ECDHKeyAgrKWPreset values (for example ECDHESA128KW).
//
// https://datatracker.ietf.org/doc/html/rfc7518#section-4.6
func NewECDHKeyAgrKWDecoder(config *ECDHKeyAgrKWDecoderConfig, preset ECDHKeyAgrKWPreset) *ECDHKeyAgrKWDecoder {
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

	if header.EPK == nil {
		return nil, fmt.Errorf(
			"(ECDHKeyAgrKWDecoder.ComputeCEK) %w: missing EPK field",
			jwt.ErrUnsupportedTokenFormat,
		)
	}

	var ecdhPayload serializers.ECDHPayload

	err := json.Unmarshal(header.EPK.Payload, &ecdhPayload)
	if err != nil {
		return nil, fmt.Errorf("(ECDHKeyAgrKWDecoder.ComputeCEK) unmarshal payload: %w", err)
	}

	_, producerPublicKey, err := serializers.DecodeECDH(&ecdhPayload)
	if err != nil {
		return nil, fmt.Errorf("(ECDHKeyAgrKWDecoder.ComputeCEK) consume producer public key: %w", err)
	}

	z, err := curve25519.X25519(decoder.config.RecipientKey.Bytes(), producerPublicKey.Bytes())
	if err != nil {
		return nil, fmt.Errorf("(ECDHKeyAgrKWDecoder.ComputeCEK) derive shared secret: %w", err)
	}

	kek, err := internal.Derive(z, string(decoder.alg), decoder.keyLen, header.APU, header.APV)
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
		return nil, fmt.Errorf("(ECDHKeyAgrKWDecoder.ComputeCEK) unwrap key: %w", err)
	}

	return cek, nil
}
