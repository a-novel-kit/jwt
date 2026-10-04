package jwek

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/a-novel-kit/jwt/v2"
	"github.com/a-novel-kit/jwt/v2/jwa"
	"github.com/a-novel-kit/jwt/v2/jwe/internal"
	"github.com/a-novel-kit/jwt/v2/jwk/serializers"
)

// ECDHKeyAgrPreset binds a content-encryption algorithm to its derived-key length
// for ECDH-ES key agreement. Use one of the predefined presets, each of which
// targets one specific encryption.
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

// ECDHKeyAgrManagerConfig holds the inputs for NewECDHKeyAgrManager. RecipientKey
// is the static half of the Diffie-Hellman exchange; ProducerInfo and RecipientInfo
// are the optional agreement party details mixed into the key derivation.
type ECDHKeyAgrManagerConfig struct {
	// Deprecated: ignored. Each token agrees on its key with a fresh ephemeral key pair, as
	// ECDH-ES requires.
	ProducerKey  *ecdh.PrivateKey
	RecipientKey *ecdh.PublicKey

	ProducerInfo  string
	RecipientInfo string
}

// ECDHKeyAgrManager implements jwe.CEKManager for ECDH-ES key agreement: it derives
// the content encryption key from a shared secret, so nothing is wrapped into the
// token. Each token draws a fresh ephemeral key pair and publishes its public half
// in the "epk" header. See RFC 7518 section 4.6.
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
// Pick the encryption whose name matches the preset: ECDHESA128CBC pairs with
// jwe.A128CBCHS256.
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

	header.JWHKeyAgreement = jwa.JWHKeyAgreement{
		APU: base64.RawURLEncoding.EncodeToString([]byte(manager.config.ProducerInfo)),
		APV: base64.RawURLEncoding.EncodeToString([]byte(manager.config.RecipientInfo)),
	}
	header.Alg = jwa.ECDHES
	header.Enc = manager.enc

	return header, nil
}

func (manager *ECDHKeyAgrManager) ComputeCEK(_ context.Context, header *jwa.JWH) ([]byte, error) {
	z, err := ephemeralAgreement(header, manager.config.RecipientKey)
	if err != nil {
		return nil, fmt.Errorf("(ECDHKeyAgrManager.ComputeCEK) %w", err)
	}

	apu, apv, err := agreementInfo(header)
	if err != nil {
		return nil, fmt.Errorf("(ECDHKeyAgrManager.ComputeCEK) %w", err)
	}

	cek, err := internal.Derive(z, string(manager.enc), manager.keyLen, apu, apv)
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
// Pick the encryption whose name matches the preset: ECDHESA128CBC pairs with
// jwe.A128CBCHS256.
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
		return nil, fmt.Errorf("(ECDHKeyAgrDecoder.ComputeCEK) %w: unmarshal payload: %w", jwt.ErrUnsupportedTokenFormat, err)
	}

	_, producerPublicKey, err := serializers.DecodeECDH(&ecdhPayload)
	if err != nil {
		return nil, fmt.Errorf("(ECDHKeyAgrDecoder.ComputeCEK) consume producer public key: %w", err)
	}

	z, err := decoder.config.RecipientKey.ECDH(producerPublicKey)
	if err != nil {
		return nil, fmt.Errorf("(ECDHKeyAgrDecoder.ComputeCEK) derive shared secret: %w", err)
	}

	apu, apv, err := agreementInfo(header)
	if err != nil {
		return nil, fmt.Errorf("(ECDHKeyAgrDecoder.ComputeCEK) %w: %w", jwt.ErrUnsupportedTokenFormat, err)
	}

	cek, err := internal.Derive(z, string(decoder.enc), decoder.keyLen, apu, apv)
	if err != nil {
		return nil, fmt.Errorf("(ECDHKeyAgrDecoder.ComputeCEK) derive key: %w", err)
	}

	return cek, nil
}

// ephemeralAgreement generates a key pair on the recipient's curve, publishes its public half as the
// header's "epk", and returns the shared secret Z. A fresh pair per token keeps every token's key
// independent of every other's.
func ephemeralAgreement(header *jwa.JWH, recipientKey *ecdh.PublicKey) ([]byte, error) {
	if recipientKey == nil {
		return nil, fmt.Errorf("%w: no recipient key", jwt.ErrInvalidSecretKey)
	}

	ephemeralKey, err := recipientKey.Curve().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ephemeral key: %w", err)
	}

	publicKeyEncoded, err := serializers.EncodeECDH(ephemeralKey.PublicKey())
	if err != nil {
		return nil, fmt.Errorf("encode ephemeral key: %w", err)
	}

	publicKeySerialized, err := json.Marshal(publicKeyEncoded)
	if err != nil {
		return nil, fmt.Errorf("serialize ephemeral key: %w", err)
	}

	header.EPK = &jwa.JWK{
		JWKCommon: jwa.JWKCommon{KTY: serializers.ECDHKeyType(recipientKey.Curve())},
		Payload:   publicKeySerialized,
	}

	z, err := ephemeralKey.ECDH(recipientKey)
	if err != nil {
		return nil, fmt.Errorf("derive shared secret: %w", err)
	}

	return z, nil
}

// agreementInfo decodes the apu/apv agreement parameters a header carries. RFC 7518 §4.6.1.2 defines
// both as base64url-encoded, and internal.Derive mixes in the decoded bytes, so the two cannot be
// the same value.
func agreementInfo(header *jwa.JWH) ([]byte, []byte, error) {
	apu, err := base64.RawURLEncoding.DecodeString(header.APU)
	if err != nil {
		return nil, nil, fmt.Errorf("decode apu: %w", err)
	}

	apv, err := base64.RawURLEncoding.DecodeString(header.APV)
	if err != nil {
		return nil, nil, fmt.Errorf("decode apv: %w", err)
	}

	return apu, apv, nil
}
