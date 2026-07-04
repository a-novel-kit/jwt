package serializers

import (
	"crypto/ecdh"
	"encoding/base64"
	"fmt"

	"github.com/a-novel-kit/jwt/jwa"
)

// An ECDHPayload wraps an ECDH-ES key in a JWKCommon format.
type ECDHPayload struct {
	// Crv is the JWK curve identifier. Only "X25519" is supported: the standard library does not implement the
	// X448 variant, so any other value makes DecodeECDH return an error. Plug in your own decoder if you need X448.
	//
	// https://github.com/golang/go/issues/29390
	Crv string `json:"crv"`
	// X is the base64url-encoded public key.
	X string `json:"x"`

	// D is the base64url-encoded private key, set only for private keys.
	D string `json:"d,omitempty"`
}

// DecodeECDH decodes the ECDH-ES key from a JWKCommon format.
func DecodeECDH(src *ECDHPayload) (*ecdh.PrivateKey, *ecdh.PublicKey, error) {
	if src.Crv != jwa.CrvX25519 {
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
