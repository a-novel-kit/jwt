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

type ECDHKeyAgrKWPreset struct {
	Alg    jwa.Alg
	KeyLen int
}

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

type ECDHKeyAgrKWManagerConfig struct {
	ProducerKey  *ecdh.PrivateKey
	RecipientKey *ecdh.PublicKey

	CEK []byte

	ProducerInfo  string
	RecipientInfo string
}

type ECDHKeyAgrKWManager struct {
	config ECDHKeyAgrKWManagerConfig

	alg    jwa.Alg
	keyLen int
}

func (manager *ECDHKeyAgrKWManager) SetHeader(_ context.Context, header *jwa.JWH) (*jwa.JWH, error) {
	if !header.Alg.Empty() {
		return nil, fmt.Errorf("(ECDHKeyAgrKWManager.SetHeader) %w: alg field already set", jwt.ErrConflictingHeader)
	}

	// Share the producer public key to the recipient. Each party requires the other one's public key in order to
	// derive the shared secret.
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

// NewECDHKeyAgrKWManager creates a new jwe.CEKManager for a key derivation using ECDH and AES Key Wrap.
//
// Use any of the ECDHKeyAgrKWPreset constants to set the algorithm and key length.
//   - ECDHESA128KW: ECDH-ES using Concat KDF and AES Key Wrap with AES-CBC-HMAC-SHA2
//   - ECDHESA192KW: ECDH-ES using Concat KDF and AES Key Wrap with AES-CBC-HMAC-SHA2
//   - ECDHESA256KW: ECDH-ES using Concat KDF and AES Key Wrap with AES-CBC-HMAC-SHA2
func NewECDHKeyAgrKWManager(
	config *ECDHKeyAgrKWManagerConfig, preset ECDHKeyAgrKWPreset,
) *ECDHKeyAgrKWManager {
	return &ECDHKeyAgrKWManager{
		config: *config,
		alg:    preset.Alg,
		keyLen: preset.KeyLen,
	}
}

type ECDHKeyAgrKWDecoderConfig struct {
	RecipientKey *ecdh.PrivateKey
}

type ECDHKeyAgrKWDecoder struct {
	config ECDHKeyAgrKWDecoderConfig

	alg    jwa.Alg
	keyLen int
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

// NewECDHKeyAgrKWDecoder creates a new jwe.CEKDecoder factory for a key derivation using ECDH and AES Key Wrap.
//
// Use any of the ECDHKeyAgrKWPreset constants to set the algorithm and key length.
//   - ECDHESA128KW: ECDH-ES using Concat KDF and AES Key Wrap with AES-CBC-HMAC-SHA2
//   - ECDHESA192KW: ECDH-ES using Concat KDF and AES Key Wrap with AES-CBC-HMAC-SHA2
//   - ECDHESA256KW: ECDH-ES using Concat KDF and AES Key Wrap with AES-CBC-HMAC-SHA2
func NewECDHKeyAgrKWDecoder(config *ECDHKeyAgrKWDecoderConfig, preset ECDHKeyAgrKWPreset) *ECDHKeyAgrKWDecoder {
	return &ECDHKeyAgrKWDecoder{
		config: *config,
		alg:    preset.Alg,
		keyLen: preset.KeyLen,
	}
}
