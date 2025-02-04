package jwek

import (
	"context"
	"crypto/ecdh"
	"encoding/json"
	"fmt"

	"golang.org/x/crypto/curve25519"

	"github.com/a-novel-kit/jwt"
	"github.com/a-novel-kit/jwt/jwa"
	"github.com/a-novel-kit/jwt/jwe/internal"
	"github.com/a-novel-kit/jwt/jwk/serializers"
)

type ECDHKeyAgrPreset struct {
	Enc    jwa.Enc
	Alg    jwa.Alg
	KeyLen int
}

var (
	ECDHESA128CBC = ECDHKeyAgrPreset{
		Enc:    jwa.A128CBC,
		KeyLen: 32,
	}
	ECDHESA192CBC = ECDHKeyAgrPreset{
		Enc:    jwa.A192CBC,
		KeyLen: 48,
	}
	ECDHESA256CBC = ECDHKeyAgrPreset{
		Enc:    jwa.A256CBC,
		KeyLen: 64,
	}

	ECDHESA128GCM = ECDHKeyAgrPreset{
		Enc:    jwa.A128GCM,
		KeyLen: 16,
	}
	ECDHESA192GCM = ECDHKeyAgrPreset{
		Enc:    jwa.A192GCM,
		KeyLen: 24,
	}
	ECDHESA256GCM = ECDHKeyAgrPreset{
		Enc:    jwa.A256GCM,
		KeyLen: 32,
	}
)

type ECDHKeyAgrManagerConfig struct {
	ProducerKey  *ecdh.PrivateKey
	RecipientKey *ecdh.PublicKey

	ProducerInfo  string
	RecipientInfo string
}

type ECDHKeyAgrManager struct {
	config ECDHKeyAgrManagerConfig

	enc    jwa.Enc
	keyLen int
}

func (manager *ECDHKeyAgrManager) SetHeader(_ context.Context, header *jwa.JWH) (*jwa.JWH, error) {
	if !header.Alg.Empty() {
		return nil, fmt.Errorf("(ECDHKeyAgrManager.SetHeader) %w: alg field already set", jwt.ErrConflictingHeader)
	}

	// Share the producer public key to the recipient. Each party requires the other one's public key in order to
	// derive the shared secret.
	publicKeyEncoded, err := serializers.EncodeECDH(manager.config.ProducerKey.PublicKey())
	if err != nil {
		return nil, fmt.Errorf("(ECDHKeyAgrManager.SetHeader) encode public key: %w", err)
	}

	publicKeySerialized, err := json.Marshal(publicKeyEncoded)
	if err != nil {
		return nil, fmt.Errorf("(ECDHKeyAgrManager.SetHeader) serialize shared public key: %w", err)
	}

	header.JWHKeyAgreement = jwa.JWHKeyAgreement{
		EPK: &jwa.JWK{Payload: publicKeySerialized},
		APU: manager.config.ProducerInfo,
		APV: manager.config.RecipientInfo,
	}
	header.Alg = jwa.ECDHES
	header.Enc = manager.enc

	return header, nil
}

func (manager *ECDHKeyAgrManager) ComputeCEK(_ context.Context, header *jwa.JWH) ([]byte, error) {
	z, err := curve25519.X25519(manager.config.ProducerKey.Bytes(), manager.config.RecipientKey.Bytes())
	if err != nil {
		return nil, fmt.Errorf("(ECDHKeyAgrManager.ComputeCEK) derive shared secret: %w", err)
	}

	cek, err := internal.Derive(z, string(manager.enc), manager.keyLen, header.APU, header.APV)
	if err != nil {
		return nil, fmt.Errorf("(ECDHKeyAgrManager.ComputeCEK) derive key: %w", err)
	}

	return cek, nil
}

func (manager *ECDHKeyAgrManager) EncryptCEK(_ context.Context, _ *jwa.JWH, _ []byte) ([]byte, error) {
	return nil, nil
}

// NewECDHKeyAgrManager creates a new jwe.CEKManager factory for a key derivation using ECDH.
//
// Use any of the ECDHKeyAgrPreset constants to set the algorithm and key length.
//   - ECDHESA128CBC: ECDH-ES using Concat KDF and CEK length of 128 bits
//   - ECDHESA192CBC: ECDH-ES using Concat KDF and CEK length of 192 bits
//   - ECDHESA256CBC: ECDH-ES using Concat KDF and CEK length of 256 bits
//   - ECDHESA128GCM: ECDH-ES using Concat KDF and CEK length of 128 bits
//   - ECDHESA192GCM: ECDH-ES using Concat KDF and CEK length of 192 bits
//   - ECDHESA256GCM: ECDH-ES using Concat KDF and CEK length of 256 bits
//
// This manager is NOT encryption agnostic.
//   - ECDHESA128CBC requires jwe.A128CBCHS256 encryption
//   - ECDHESA192CBC requires jwe.A192CBCHS384 encryption
//   - ECDHESA256CBC requires jwe.A256CBCHS512 encryption
//   - ECDHESA128GCM requires jwe.A128GCM encryption
//   - ECDHESA192GCM requires jwe.A192GCM encryption
//   - ECDHESA256GCM requires jwe.A256GCM encryption
//
// https://datatracker.ietf.org/doc/html/rfc7518#section-4.6
func NewECDHKeyAgrManager(config *ECDHKeyAgrManagerConfig, preset ECDHKeyAgrPreset) *ECDHKeyAgrManager {
	return &ECDHKeyAgrManager{
		config: *config,
		enc:    preset.Enc,
		keyLen: preset.KeyLen,
	}
}

type ECDHKeyAgrDecoderConfig struct {
	RecipientKey *ecdh.PrivateKey
}

type ECDHKeyAgrDecoder struct {
	config ECDHKeyAgrDecoderConfig

	enc    jwa.Enc
	keyLen int
}

func (decoder *ECDHKeyAgrDecoder) ComputeCEK(_ context.Context, header *jwa.JWH, encKey []byte) ([]byte, error) {
	if header.Alg != jwa.ECDHES {
		return nil, fmt.Errorf(
			"(ECDHKeyAgrDecoder.ComputeCEK) %w: invalid algorithm %s, expected %s",
			jwt.ErrMismatchRecipientPlugin, header.Alg, jwa.ECDHES,
		)
	}

	if header.Enc != decoder.enc {
		return nil, fmt.Errorf(
			"(ECDHKeyAgrDecoder.ComputeCEK) %w: invalid encryption %s, expected %s",
			jwt.ErrConflictingHeader, header.Enc, decoder.enc,
		)
	}

	if len(encKey) != 0 {
		return nil, fmt.Errorf(
			"(ECDHKeyAgrDecoder.ComputeCEK) %w: unexpected enc key (should be empty)",
			jwt.ErrUnsupportedTokenFormat,
		)
	}

	if header.EPK == nil {
		return nil, fmt.Errorf(
			"(ECDHKeyAgrDecoder.ComputeCEK) %w: missing EPK field",
			jwt.ErrUnsupportedTokenFormat,
		)
	}

	var ecdhPayload serializers.ECDHPayload
	if err := json.Unmarshal(header.EPK.Payload, &ecdhPayload); err != nil {
		return nil, fmt.Errorf("(ECDHKeyAgrDecoder.ComputeCEK) unmarshal payload: %w", err)
	}

	_, producerPublicKey, err := serializers.DecodeECDH(&ecdhPayload)
	if err != nil {
		return nil, fmt.Errorf("(ECDHKeyAgrDecoder.ComputeCEK) consume producer public key: %w", err)
	}

	z, err := curve25519.X25519(decoder.config.RecipientKey.Bytes(), producerPublicKey.Bytes())
	if err != nil {
		return nil, fmt.Errorf("(ECDHKeyAgrDecoder.ComputeCEK) derive shared secret: %w", err)
	}

	cek, err := internal.Derive(z, string(decoder.enc), decoder.keyLen, header.APU, header.APV)
	if err != nil {
		return nil, fmt.Errorf("(ECDHKeyAgrDecoder.ComputeCEK) derive key: %w", err)
	}

	return cek, nil
}

// NewECDHKeyAgrDecoder creates a new jwe.CEKDecoder factory for a key derivation using ECDH.
//
// Use any of the ECDHKeyAgrPreset constants to set the algorithm and key length.
//   - ECDHESA128CBC: ECDH-ES using Concat KDF and CEK length of 128 bits
//   - ECDHESA192CBC: ECDH-ES using Concat KDF and CEK length of 192 bits
//   - ECDHESA256CBC: ECDH-ES using Concat KDF and CEK length of 256 bits
//   - ECDHESA128GCM: ECDH-ES using Concat KDF and CEK length of 128 bits
//   - ECDHESA192GCM: ECDH-ES using Concat KDF and CEK length of 192 bits
//   - ECDHESA256GCM: ECDH-ES using Concat KDF and CEK length of 256 bits
//
// This manager is NOT encryption agnostic.
//   - ECDHESA128CBC requires jwe.A128CBCHS256 encryption
//   - ECDHESA192CBC requires jwe.A192CBCHS384 encryption
//   - ECDHESA256CBC requires jwe.A256CBCHS512 encryption
//   - ECDHESA128GCM requires jwe.A128GCM encryption
//   - ECDHESA192GCM requires jwe.A192GCM encryption
//   - ECDHESA256GCM requires jwe.A256GCM encryption
//
// https://datatracker.ietf.org/doc/html/rfc7518#section-4.6
func NewECDHKeyAgrDecoder(config *ECDHKeyAgrDecoderConfig, preset ECDHKeyAgrPreset) *ECDHKeyAgrDecoder {
	return &ECDHKeyAgrDecoder{
		config: *config,
		enc:    preset.Enc,
		keyLen: preset.KeyLen,
	}
}
