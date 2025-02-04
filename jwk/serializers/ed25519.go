package serializers

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
)

// EDPayload wraps a EDDSA key in a JWKCommon format.
type EDPayload struct {
	// Crv (curve) parameter.
	//
	// Since the proposal of adding 448 curve variants to the standard library was declined due to complexity and
	// low benefits, it is currently not supported by this library. Thus, using a curve value other than "Ed25519"
	// will throw an error.
	//
	// https://github.com/golang/go/issues/29390
	//
	// You may still use your own decoded that supports x448.
	Crv string `json:"crv"`
	// X coordinate parameter.
	X string `json:"x"`

	// PRIVATE KEY.

	// D (ECC private key) parameter.
	D string `json:"d,omitempty"`
}

var ErrInvalidEDKey = errors.New("invalid EdDSA key")

// DecodeED decodes the EdDSA key from a JWKCommon format.
func DecodeED(src *EDPayload) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	if src.Crv != "Ed25519" {
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
