package jwek

import (
	"context"
	"crypto/ecdh"
	"encoding/json"
	"fmt"

	"golang.org/x/crypto/curve25519"

	"github.com/a-novel-kit/jwt/v2"
	"github.com/a-novel-kit/jwt/v2/jwa"
	"github.com/a-novel-kit/jwt/v2/jwe/internal"
	"github.com/a-novel-kit/jwt/v2/jwk/serializers"
)

// ECDHKeyAgrPreset binds a content-encryption algorithm to its derived-key length
// for ECDH-ES key agreement. Each preset targets one specific encryption and is
// not interchangeable. Use one of the predefined presets rather than building one
// by hand.
type ECDHKeyAgrPreset struct {
	Enc    jwa.Enc
	Alg    jwa.Alg
	KeyLen int
}

// The ECDH-ES presets, one per supported content-encryption algorithm.
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

// ECDHKeyAgrManagerConfig holds the inputs for NewECDHKeyAgrManager. ProducerKey
// and RecipientKey are the two halves of the Diffie-Hellman exchange; ProducerInfo
// and RecipientInfo are the optional agreement party details mixed into the key
// derivation.
type ECDHKeyAgrManagerConfig struct {
	ProducerKey  *ecdh.PrivateKey
	RecipientKey *ecdh.PublicKey

	ProducerInfo  string
	RecipientInfo string
}

// ECDHKeyAgrManager implements jwe.CEKManager for ECDH-ES key agreement: it derives
// the content encryption key from a shared secret instead of wrapping one into the
// token. See RFC 7518 section 4.6.
type ECDHKeyAgrManager struct {
	config ECDHKeyAgrManagerConfig

	enc    jwa.Enc
	keyLen int
}

// NewECDHKeyAgrManager creates a jwe.CEKManager that derives the content
// encryption key with ECDH-ES using the Concat KDF. The preset selects the
// content-encryption algorithm and derived-key length; use one of the
// ECDHKeyAgrPreset values (for example ECDHESA128CBC).
//
// The preset is bound to a specific jwe encryption and is not interchangeable:
// pick the encryption whose name matches the preset (for example ECDHESA128CBC
// pairs with jwe.A128CBCHS256).
//
// https://datatracker.ietf.org/doc/html/rfc7518#section-4.6
func NewECDHKeyAgrManager(config *ECDHKeyAgrManagerConfig, preset ECDHKeyAgrPreset) *ECDHKeyAgrManager {
	return &ECDHKeyAgrManager{
		config: *config,
		enc:    preset.Enc,
		keyLen: preset.KeyLen,
	}
}

func (manager *ECDHKeyAgrManager) SetHeader(_ context.Context, header *jwa.JWH) (*jwa.JWH, error) {
	if !header.Alg.Empty() {
		return nil, fmt.Errorf("(ECDHKeyAgrManager.SetHeader) %w: alg field already set", jwt.ErrConflictingHeader)
	}

	// Publish the producer public key in the header: the recipient needs it to
	// derive the same shared secret from its own private key.
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

// ECDHKeyAgrDecoderConfig holds the recipient private key used to reconstruct the
// shared secret from the producer public key carried in the token header.
type ECDHKeyAgrDecoderConfig struct {
	RecipientKey *ecdh.PrivateKey
}

// ECDHKeyAgrDecoder implements jwe.CEKDecoder for ECDH-ES key agreement, deriving
// the content encryption key from the shared secret. See RFC 7518 section 4.6.
type ECDHKeyAgrDecoder struct {
	config ECDHKeyAgrDecoderConfig

	enc    jwa.Enc
	keyLen int
}

// NewECDHKeyAgrDecoder creates a jwe.CEKDecoder that derives the content
// encryption key with ECDH-ES using the Concat KDF. The preset must match the one
// used to encrypt the token; use one of the ECDHKeyAgrPreset values (for example
// ECDHESA128CBC).
//
// The preset is bound to a specific jwe encryption and is not interchangeable:
// pick the encryption whose name matches the preset (for example ECDHESA128CBC
// pairs with jwe.A128CBCHS256).
//
// https://datatracker.ietf.org/doc/html/rfc7518#section-4.6
func NewECDHKeyAgrDecoder(config *ECDHKeyAgrDecoderConfig, preset ECDHKeyAgrPreset) *ECDHKeyAgrDecoder {
	return &ECDHKeyAgrDecoder{
		config: *config,
		enc:    preset.Enc,
		keyLen: preset.KeyLen,
	}
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

	err := json.Unmarshal(header.EPK.Payload, &ecdhPayload)
	if err != nil {
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
