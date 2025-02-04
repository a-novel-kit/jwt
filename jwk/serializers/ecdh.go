package serializers

import (
	"crypto/ecdh"
	"encoding/base64"
	"fmt"
)

// ECDHPayload wraps a ECDH-ES key in a JWKCommon format.
type ECDHPayload struct {
	// Crv (curve) parameter.
	//
	// Since the proposal of adding 448 curve variants to the standard library was declined due to complexity and
	// low benefits, it is currently not supported by this library. Thus, using a curve value other than "X25519"
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

// DecodeECDH decodes the ECDH-ES key from a JWKCommon format.
func DecodeECDH(src *ECDHPayload) (*ecdh.PrivateKey, *ecdh.PublicKey, error) {
	if src.Crv != "X25519" {
		return nil, nil, ErrUnsupportedCurve
	}

	publicKey, err := base64.RawURLEncoding.DecodeString(src.X)
	if err != nil {
		return nil, nil, fmt.Errorf("decode ecdh public key: %w", err)
	}

	ecdhPubKey, err := ecdh.X25519().NewPublicKey(publicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("create ecdh public key: %w", err)
	}

	if src.D == "" {
		return nil, ecdhPubKey, nil
	}

	privateKey, err := base64.RawURLEncoding.DecodeString(src.D)
	if err != nil {
		return nil, nil, fmt.Errorf("decode ecdh private key: %w", err)
	}

	ecdhPrivKey, err := ecdh.X25519().NewPrivateKey(privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("create ecdh private key: %w", err)
	}

	return ecdhPrivKey, ecdhPubKey, nil
}

// EncodeECDH encodes the ECDH-ES key into a JWKCommon format.
func EncodeECDH[Key *ecdh.PublicKey | *ecdh.PrivateKey](key Key) (*ECDHPayload, error) {
	pubKey, ok := any(key).(*ecdh.PublicKey)
	if ok {
		pubKeyBytes := pubKey.Bytes()
		encPubKey := base64.RawURLEncoding.EncodeToString(pubKeyBytes)

		return &ECDHPayload{
			Crv: "X25519",
			X:   encPubKey,
		}, nil
	}

	privKey := any(key).(*ecdh.PrivateKey)

	encPubKey := base64.RawURLEncoding.EncodeToString(privKey.Public().(*ecdh.PublicKey).Bytes())
	encPrivKey := base64.RawURLEncoding.EncodeToString(privKey.Bytes())

	return &ECDHPayload{
		Crv: "X25519",
		X:   encPubKey,
		D:   encPrivKey,
	}, nil
}
