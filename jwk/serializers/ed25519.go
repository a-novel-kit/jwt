package serializers

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/a-novel-kit/jwt/jwa"
)

// An EDPayload wraps an EdDSA key in a JWKCommon format.
type EDPayload struct {
	// Crv is the JWK curve identifier. Only "Ed25519" is supported: the standard library does not implement the
	// Ed448 variant, so any other value makes DecodeED return an error. Plug in your own decoder if you need Ed448.
	//
	// https://github.com/golang/go/issues/29390
	Crv string `json:"crv"`
	// X is the base64url-encoded public key.
	X string `json:"x"`

	// D is the base64url-encoded private key, set only for private keys.
	D string `json:"d,omitempty"`
}

// ErrInvalidEDKey is returned when a decoded EdDSA key does not have the size Ed25519 requires.
var ErrInvalidEDKey = errors.New("invalid EdDSA key")

// DecodeED decodes the EdDSA key from a JWKCommon format.
func DecodeED(src *EDPayload) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	if src.Crv != jwa.CrvEd25519 {
		return nil, nil, ErrUnsupportedCurve
	}

	publicKey, err := base64.RawURLEncoding.DecodeString(src.X)
	if err != nil {
		return nil, nil, fmt.Errorf("decode eddsa public key: %w", err)
	}

	if len(publicKey) != ed25519.PublicKeySize {
		return nil, nil, fmt.Errorf("%w: invalid public key size", ErrInvalidEDKey)
	}

	edPubKey := ed25519.PublicKey(publicKey)

	if src.D == "" {
		return nil, edPubKey, nil
	}

	privateKey, err := base64.RawURLEncoding.DecodeString(src.D)
	if err != nil {
		return nil, nil, fmt.Errorf("decode eddsa private key: %w", err)
	}

	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, nil, fmt.Errorf("%w: invalid private key size", ErrInvalidEDKey)
	}

	edPrivKey := ed25519.PrivateKey(privateKey)

	return edPrivKey, edPubKey, nil
}

// EncodeED returns the JWKCommon representation of an EdDSA key.
func EncodeED[Key ed25519.PublicKey | ed25519.PrivateKey](key Key) *EDPayload {
	pubKey, ok := any(key).(ed25519.PublicKey)
	if ok {
		encodedPub := base64.RawURLEncoding.EncodeToString(pubKey)

		return &EDPayload{
			Crv: "Ed25519",
			X:   encodedPub,
		}
	}

	privKey := any(key).(ed25519.PrivateKey)

	encodedPub := base64.RawURLEncoding.EncodeToString(privKey.Public().(ed25519.PublicKey))
	encodedPriv := base64.RawURLEncoding.EncodeToString(privKey)

	return &EDPayload{
		Crv: "Ed25519",
		X:   encodedPub,
		D:   encodedPriv,
	}
}
