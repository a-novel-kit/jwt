package jwe

import (
	"context"
	"crypto/ecdh"
	"crypto/hpke"
	"encoding/base64"
	"fmt"

	"github.com/a-novel-kit/jwt/v2"
	"github.com/a-novel-kit/jwt/v2/jwa"
)

// HPKEPreset holds one HPKE Integrated Encryption suite: the "alg" identifier, the curve its
// Diffie-Hellman KEM runs on, and its key derivation function and AEAD. Use one of the package presets.
type HPKEPreset struct {
	Alg   jwa.Alg
	Curve ecdh.Curve
	KDF   hpke.KDF
	AEAD  hpke.AEAD
}

// The HPKE Integrated Encryption suites.
//
// https://datatracker.ietf.org/doc/html/draft-ietf-jose-hpke-encrypt#section-5.1
var (
	// HPKE0 is DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, and AES-128-GCM.
	HPKE0 = HPKEPreset{Alg: jwa.HPKE0, Curve: ecdh.P256(), KDF: hpke.HKDFSHA256(), AEAD: hpke.AES128GCM()}
	// HPKE1 is DHKEM(P-384, HKDF-SHA384), HKDF-SHA384, and AES-256-GCM.
	HPKE1 = HPKEPreset{Alg: jwa.HPKE1, Curve: ecdh.P384(), KDF: hpke.HKDFSHA384(), AEAD: hpke.AES256GCM()}
	// HPKE2 is DHKEM(P-521, HKDF-SHA512), HKDF-SHA512, and AES-256-GCM.
	HPKE2 = HPKEPreset{Alg: jwa.HPKE2, Curve: ecdh.P521(), KDF: hpke.HKDFSHA512(), AEAD: hpke.AES256GCM()}
	// HPKE3 is DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, and AES-128-GCM.
	HPKE3 = HPKEPreset{Alg: jwa.HPKE3, Curve: ecdh.X25519(), KDF: hpke.HKDFSHA256(), AEAD: hpke.AES128GCM()}
	// HPKE4 is DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, and ChaCha20-Poly1305.
	HPKE4 = HPKEPreset{Alg: jwa.HPKE4, Curve: ecdh.X25519(), KDF: hpke.HKDFSHA256(), AEAD: hpke.ChaCha20Poly1305()}
	// HPKE7 is DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, and AES-256-GCM.
	HPKE7 = HPKEPreset{Alg: jwa.HPKE7, Curve: ecdh.P256(), KDF: hpke.HKDFSHA256(), AEAD: hpke.AES256GCM()}
)

// HPKEEncryptionConfig configures NewHPKEEncryption with the recipient public key the payload is
// encrypted to.
type HPKEEncryptionConfig struct {
	RecipientKey *ecdh.PublicKey
}

// HPKEEncryption is a jwt.ProducerPlugin that encrypts a token payload with HPKE Integrated
// Encryption: HPKE seals the payload itself, so the token carries no "enc" and no content
// encryption key. Each token draws a fresh encapsulated secret. Create it with NewHPKEEncryption.
type HPKEEncryption struct {
	recipientKey *ecdh.PublicKey
	preset       HPKEPreset
}

// NewHPKEEncryption creates a jwt.ProducerPlugin that encrypts a token payload to the recipient key
// with HPKE. The key must lie on the preset's curve; pass one of the package's HPKEPreset values.
//
// https://datatracker.ietf.org/doc/html/draft-ietf-jose-hpke-encrypt#section-5
func NewHPKEEncryption(config *HPKEEncryptionConfig, preset HPKEPreset) *HPKEEncryption {
	return &HPKEEncryption{
		recipientKey: config.RecipientKey,
		preset:       preset,
	}
}

func (enc *HPKEEncryption) Header(_ context.Context, header *jwa.JWH) (*jwa.JWH, error) {
	if !header.Alg.Empty() || header.Enc != "" {
		return nil, fmt.Errorf("(HPKEEncryption.Header) %w: alg or enc field already set", jwt.ErrConflictingHeader)
	}

	if enc.recipientKey == nil || enc.recipientKey.Curve() != enc.preset.Curve {
		return nil, fmt.Errorf(
			"(HPKEEncryption.Header) %w: %s needs a recipient key on %v",
			jwt.ErrInvalidSecretKey, enc.preset.Alg, enc.preset.Curve,
		)
	}

	header.Alg = enc.preset.Alg

	return header, nil
}

func (enc *HPKEEncryption) Transform(_ context.Context, _ *jwa.JWH, rawToken string) (string, error) {
	token, err := jwt.DecodeToken(rawToken, &jwt.RawTokenDecoder{})
	if err != nil {
		return "", fmt.Errorf("(HPKEEncryption.Transform) split token: %w", err)
	}

	plainText, err := base64.RawURLEncoding.DecodeString(token.Payload)
	if err != nil {
		return "", fmt.Errorf("(HPKEEncryption.Transform) decode payload: %w", err)
	}

	publicKey, err := hpke.NewDHKEMPublicKey(enc.recipientKey)
	if err != nil {
		return "", fmt.Errorf("(HPKEEncryption.Transform) %w: %w", jwt.ErrInvalidSecretKey, err)
	}

	encapsulated, sender, err := hpke.NewSender(publicKey, enc.preset.KDF, enc.preset.AEAD, nil)
	if err != nil {
		return "", fmt.Errorf("(HPKEEncryption.Transform) set up sender: %w", err)
	}

	// The AAD is the encoded protected header, which key management leaves unchanged in this mode.
	cipherText, err := sender.Seal([]byte(token.Header), plainText)
	if err != nil {
		return "", fmt.Errorf("(HPKEEncryption.Transform) seal: %w", err)
	}

	// The encapsulated secret takes the encrypted key's place; the IV and tag stay empty.
	return jwt.EncryptedToken{
		Header:     token.Header,
		EncKey:     base64.RawURLEncoding.EncodeToString(encapsulated),
		CipherText: base64.RawURLEncoding.EncodeToString(cipherText),
	}.String(), nil
}

// HPKEDecryptionConfig configures NewHPKEDecryption with the recipient private key.
type HPKEDecryptionConfig struct {
	RecipientKey *ecdh.PrivateKey
}

// HPKEDecryption is a jwt.RecipientPlugin that decrypts a token encrypted with HPKE Integrated
// Encryption. It implements HPKE's base mode and refuses a token naming a pre-shared key. Create it
// with NewHPKEDecryption.
type HPKEDecryption struct {
	recipientKey *ecdh.PrivateKey
	preset       HPKEPreset
}

// NewHPKEDecryption creates a jwt.RecipientPlugin that decrypts a token encrypted with HPKE. The
// preset must match the one used at encryption.
//
// https://datatracker.ietf.org/doc/html/draft-ietf-jose-hpke-encrypt#section-7.2
func NewHPKEDecryption(config *HPKEDecryptionConfig, preset HPKEPreset) *HPKEDecryption {
	return &HPKEDecryption{
		recipientKey: config.RecipientKey,
		preset:       preset,
	}
}

func (dec *HPKEDecryption) Transform(_ context.Context, header *jwa.JWH, rawToken string) ([]byte, error) {
	if header.Alg != dec.preset.Alg {
		return nil, fmt.Errorf(
			"(HPKEDecryption.Transform) %w: invalid algorithm %s, expected %s",
			jwt.ErrMismatchRecipientPlugin, header.Alg, dec.preset.Alg,
		)
	}

	// Integrated Encryption forbids "enc" and "ek"; "psk_id" selects a mode this package lacks, and
	// "zip" a decompression it does not perform.
	if header.Enc != "" || header.EK != "" || header.PSKID != "" || header.Zip != "" {
		return nil, fmt.Errorf(
			"(HPKEDecryption.Transform) %w: unsupported enc, ek, psk_id or zip parameter", jwt.ErrUnsupportedTokenFormat,
		)
	}

	if dec.recipientKey == nil || dec.recipientKey.Curve() != dec.preset.Curve {
		return nil, fmt.Errorf(
			"(HPKEDecryption.Transform) %w: %s needs a recipient key on %v",
			jwt.ErrInvalidSecretKey, dec.preset.Alg, dec.preset.Curve,
		)
	}

	token, err := jwt.DecodeToken(rawToken, &jwt.EncryptedTokenDecoder{})
	if err != nil {
		return nil, fmt.Errorf("(HPKEDecryption.Transform) split token: %w", err)
	}

	if token.IV != "" || token.Tag != "" {
		return nil, fmt.Errorf("(HPKEDecryption.Transform) %w: iv and tag must be empty", ErrInvalidToken)
	}

	encapsulated, err := base64.RawURLEncoding.DecodeString(token.EncKey)
	if err != nil {
		return nil, fmt.Errorf("(HPKEDecryption.Transform) %w: decode enc key: %w", jwt.ErrUnsupportedTokenFormat, err)
	}

	cipherText, err := base64.RawURLEncoding.DecodeString(token.CipherText)
	if err != nil {
		return nil, fmt.Errorf("(HPKEDecryption.Transform) %w: decode cipher text: %w", jwt.ErrUnsupportedTokenFormat, err)
	}

	privateKey, err := hpke.NewDHKEMPrivateKey(dec.recipientKey)
	if err != nil {
		return nil, fmt.Errorf("(HPKEDecryption.Transform) %w: %w", jwt.ErrInvalidSecretKey, err)
	}

	recipient, err := hpke.NewRecipient(encapsulated, privateKey, dec.preset.KDF, dec.preset.AEAD, nil)
	if err != nil {
		return nil, fmt.Errorf("(HPKEDecryption.Transform) %w: decapsulate: %w", ErrInvalidToken, err)
	}

	plainText, err := recipient.Open([]byte(token.Header), cipherText)
	if err != nil {
		// An authenticated-decryption failure, like a bad AES-GCM tag.
		return nil, fmt.Errorf("(HPKEDecryption.Transform) %w: %w", ErrInvalidSecret, err)
	}

	return plainText, nil
}
