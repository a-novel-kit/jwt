package jwek

import (
	"context"
	"crypto/ecdh"
	"crypto/hpke"
	"encoding/base64"
	"fmt"

	"github.com/a-novel-kit/jwt/v2"
	"github.com/a-novel-kit/jwt/v2/jwa"
)

// HPKEKeyEncPreset holds one HPKE Key Encryption suite: the "alg" identifier, the curve its
// Diffie-Hellman KEM runs on, and its key derivation function and AEAD. Use one of the predefined
// presets.
type HPKEKeyEncPreset struct {
	Alg   jwa.Alg
	Curve ecdh.Curve
	KDF   hpke.KDF
	AEAD  hpke.AEAD
}

// The HPKE Key Encryption suites.
//
// https://datatracker.ietf.org/doc/html/draft-ietf-jose-hpke-encrypt#section-6.2
var (
	HPKE0KE = HPKEKeyEncPreset{Alg: jwa.HPKE0KE, Curve: ecdh.P256(), KDF: hpke.HKDFSHA256(), AEAD: hpke.AES128GCM()}
	HPKE1KE = HPKEKeyEncPreset{Alg: jwa.HPKE1KE, Curve: ecdh.P384(), KDF: hpke.HKDFSHA384(), AEAD: hpke.AES256GCM()}
	HPKE2KE = HPKEKeyEncPreset{Alg: jwa.HPKE2KE, Curve: ecdh.P521(), KDF: hpke.HKDFSHA512(), AEAD: hpke.AES256GCM()}
	HPKE3KE = HPKEKeyEncPreset{Alg: jwa.HPKE3KE, Curve: ecdh.X25519(), KDF: hpke.HKDFSHA256(), AEAD: hpke.AES128GCM()}
	HPKE7KE = HPKEKeyEncPreset{Alg: jwa.HPKE7KE, Curve: ecdh.P256(), KDF: hpke.HKDFSHA256(), AEAD: hpke.AES256GCM()}
)

// recipientStructure builds the HPKE info of Key Encryption, which binds the encrypted CEK to the
// content encryption algorithm. This package sets no recipient_extra_info, so that field is empty.
//
// https://datatracker.ietf.org/doc/html/draft-ietf-jose-hpke-encrypt#section-6.1
func recipientStructure(enc jwa.Enc) []byte {
	info := append([]byte("JOSE-HPKE rcpt"), 0xff)
	info = append(info, enc...)

	return append(info, 0xff)
}

// HPKEKeyEncManagerConfig holds the recipient public key each token's content encryption key is
// encrypted to.
type HPKEKeyEncManagerConfig struct {
	RecipientKey *ecdh.PublicKey
}

// HPKEKeyEncManager implements jwe.CEKManager: it encrypts a fresh content encryption key per token
// to the recipient with HPKE, publishing the encapsulated secret in the "ek" header.
type HPKEKeyEncManager struct {
	recipientKey *ecdh.PublicKey
	preset       HPKEKeyEncPreset
}

// NewHPKEKeyEncManager creates a jwe.CEKManager that encrypts the content encryption key with HPKE.
// The key must lie on the preset's curve; use one of the HPKEKeyEncPreset values (for example
// HPKE0KE).
//
// https://datatracker.ietf.org/doc/html/draft-ietf-jose-hpke-encrypt#section-6
func NewHPKEKeyEncManager(config *HPKEKeyEncManagerConfig, preset HPKEKeyEncPreset) *HPKEKeyEncManager {
	return &HPKEKeyEncManager{
		recipientKey: config.RecipientKey,
		preset:       preset,
	}
}

func (manager *HPKEKeyEncManager) SetHeader(_ context.Context, header *jwa.JWH) (*jwa.JWH, error) {
	if !header.Alg.Empty() {
		return nil, fmt.Errorf("(HPKEKeyEncManager.SetHeader) %w: alg field already set", jwt.ErrConflictingHeader)
	}

	if manager.recipientKey == nil || manager.recipientKey.Curve() != manager.preset.Curve {
		return nil, fmt.Errorf(
			"(HPKEKeyEncManager.SetHeader) %w: %s needs a recipient key on %v",
			jwt.ErrInvalidSecretKey, manager.preset.Alg, manager.preset.Curve,
		)
	}

	header.Alg = manager.preset.Alg

	return header, nil
}

func (manager *HPKEKeyEncManager) ComputeCEK(_ context.Context, header *jwa.JWH) ([]byte, error) {
	cek, err := newCEK(header)
	if err != nil {
		return nil, fmt.Errorf("(HPKEKeyEncManager.ComputeCEK) %w", err)
	}

	return cek, nil
}

func (manager *HPKEKeyEncManager) EncryptCEK(_ context.Context, header *jwa.JWH, cek []byte) ([]byte, error) {
	publicKey, err := hpke.NewDHKEMPublicKey(manager.recipientKey)
	if err != nil {
		return nil, fmt.Errorf("(HPKEKeyEncManager.EncryptCEK) %w: %w", jwt.ErrInvalidSecretKey, err)
	}

	encapsulated, sender, err := hpke.NewSender(
		publicKey, manager.preset.KDF, manager.preset.AEAD, recipientStructure(header.Enc),
	)
	if err != nil {
		return nil, fmt.Errorf("(HPKEKeyEncManager.EncryptCEK) set up sender: %w", err)
	}

	encrypted, err := sender.Seal(nil, cek)
	if err != nil {
		return nil, fmt.Errorf("(HPKEKeyEncManager.EncryptCEK) seal: %w", err)
	}

	header.EK = base64.RawURLEncoding.EncodeToString(encapsulated)

	return encrypted, nil
}

// HPKEKeyEncDecoderConfig holds the recipient private key that decrypts the content encryption key.
type HPKEKeyEncDecoderConfig struct {
	RecipientKey *ecdh.PrivateKey
}

// HPKEKeyEncDecoder implements jwe.CEKDecoder, decrypting a content encryption key encrypted with
// HPKE. It implements HPKE's base mode and refuses a token naming a pre-shared key.
type HPKEKeyEncDecoder struct {
	recipientKey *ecdh.PrivateKey
	preset       HPKEKeyEncPreset
}

// NewHPKEKeyEncDecoder creates a jwe.CEKDecoder that decrypts an HPKE-encrypted content encryption
// key. The preset must match the one used to encrypt the token.
//
// https://datatracker.ietf.org/doc/html/draft-ietf-jose-hpke-encrypt#section-6
func NewHPKEKeyEncDecoder(config *HPKEKeyEncDecoderConfig, preset HPKEKeyEncPreset) *HPKEKeyEncDecoder {
	return &HPKEKeyEncDecoder{
		recipientKey: config.RecipientKey,
		preset:       preset,
	}
}

func (decoder *HPKEKeyEncDecoder) ComputeCEK(_ context.Context, header *jwa.JWH, encKey []byte) ([]byte, error) {
	if header.Alg != decoder.preset.Alg {
		return nil, fmt.Errorf(
			"(HPKEKeyEncDecoder.ComputeCEK) %w: invalid algorithm %s, expected %s",
			jwt.ErrMismatchRecipientPlugin, header.Alg, decoder.preset.Alg,
		)
	}

	if header.PSKID != "" {
		return nil, fmt.Errorf("(HPKEKeyEncDecoder.ComputeCEK) %w: psk_id is not supported", jwt.ErrUnsupportedTokenFormat)
	}

	if decoder.recipientKey == nil || decoder.recipientKey.Curve() != decoder.preset.Curve {
		return nil, fmt.Errorf(
			"(HPKEKeyEncDecoder.ComputeCEK) %w: %s needs a recipient key on %v",
			jwt.ErrInvalidSecretKey, decoder.preset.Alg, decoder.preset.Curve,
		)
	}

	encapsulated, err := base64.RawURLEncoding.DecodeString(header.EK)
	if err != nil || len(encapsulated) == 0 {
		return nil, fmt.Errorf("(HPKEKeyEncDecoder.ComputeCEK) %w: missing or undecodable ek", jwt.ErrUnsupportedTokenFormat)
	}

	privateKey, err := hpke.NewDHKEMPrivateKey(decoder.recipientKey)
	if err != nil {
		return nil, fmt.Errorf("(HPKEKeyEncDecoder.ComputeCEK) %w: %w", jwt.ErrInvalidSecretKey, err)
	}

	recipient, err := hpke.NewRecipient(
		encapsulated, privateKey, decoder.preset.KDF, decoder.preset.AEAD, recipientStructure(header.Enc),
	)
	if err != nil {
		return nil, fmt.Errorf("(HPKEKeyEncDecoder.ComputeCEK) decapsulate: %w", err)
	}

	cek, err := recipient.Open(nil, encKey)
	if err != nil {
		return nil, fmt.Errorf("(HPKEKeyEncDecoder.ComputeCEK) decrypt cek: %w", err)
	}

	return cek, nil
}
