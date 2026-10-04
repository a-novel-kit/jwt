package serializers

import (
	"crypto/ecdh"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/a-novel-kit/jwt/v2/jwa"
)

// An ECDHPayload wraps a key-agreement key in a JWKCommon format: an "OKP" key for X25519 (RFC 8037)
// or an "EC" key for the NIST curves (RFC 7518 §6.2).
type ECDHPayload struct {
	// Crv is the JWK curve identifier: "X25519", "P-256", "P-384", or "P-521". The standard library does
	// not implement X448, so that value makes DecodeECDH return an error.
	//
	// https://github.com/golang/go/issues/29390
	Crv string `json:"crv"`
	// X is the base64url-encoded public key on X25519, or the x coordinate of the public point on a
	// NIST curve.
	X string `json:"x"`
	// Y is the base64url-encoded y coordinate of the public point, set only on a NIST curve.
	Y string `json:"y,omitempty"`

	// D is the base64url-encoded private key, set only for private keys.
	D string `json:"d,omitempty"`
}

// ErrInvalidECDHKey is returned when a decoded key-agreement key is not a valid point or scalar for
// its curve, or when its private and public halves do not belong together.
var ErrInvalidECDHKey = errors.New("invalid ECDH key")

// ecdhCurves lists the curves a key-agreement JWK can name, by their "crv" value.
var ecdhCurves = map[string]ecdh.Curve{
	jwa.CrvX25519: ecdh.X25519(),
	"P-256":       ecdh.P256(),
	"P-384":       ecdh.P384(),
	"P-521":       ecdh.P521(),
}

// ECDHKeyType returns the JWK key type a key-agreement key on curve serializes under: "OKP" for
// X25519, "EC" for the NIST curves.
func ECDHKeyType(curve ecdh.Curve) jwa.KTY {
	if curve == ecdh.X25519() {
		return jwa.KTYOKP
	}

	return jwa.KTYEC
}

// DecodeECDH decodes the key-agreement key from a JWKCommon format. Each NIST coordinate has to span
// the full size of its curve's field, as RFC 7518 §6.2.1.2 requires.
func DecodeECDH(src *ECDHPayload) (*ecdh.PrivateKey, *ecdh.PublicKey, error) {
	curve, ok := ecdhCurves[src.Crv]
	if !ok {
		return nil, nil, ErrUnsupportedCurve
	}

	publicKey, err := base64.RawURLEncoding.DecodeString(src.X)
	if err != nil {
		return nil, nil, fmt.Errorf("decode ecdh public key: %w", err)
	}

	// A NIST public key is the uncompressed point: 0x04, then both coordinates.
	if curve != ecdh.X25519() {
		y, err := base64.RawURLEncoding.DecodeString(src.Y)
		if err != nil {
			return nil, nil, fmt.Errorf("decode ecdh public key y: %w", err)
		}

		if len(publicKey) != len(y) {
			return nil, nil, fmt.Errorf("%w: x and y differ in size", ErrInvalidECDHKey)
		}

		publicKey = append(append([]byte{4}, publicKey...), y...)
	}

	ecdhPubKey, err := curve.NewPublicKey(publicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrInvalidECDHKey, err)
	}

	if src.D == "" {
		return nil, ecdhPubKey, nil
	}

	privateKey, err := base64.RawURLEncoding.DecodeString(src.D)
	if err != nil {
		return nil, nil, fmt.Errorf("decode ecdh private key: %w", err)
	}

	ecdhPrivKey, err := curve.NewPrivateKey(privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrInvalidECDHKey, err)
	}

	// A private key that does not match "x" agrees on a secret no holder of the public key can derive.
	if !ecdhPrivKey.PublicKey().Equal(ecdhPubKey) {
		return nil, nil, fmt.Errorf("%w: private key does not match public key", ErrInvalidECDHKey)
	}

	return ecdhPrivKey, ecdhPubKey, nil
}

// EncodeECDH encodes the key-agreement key into a JWKCommon format.
func EncodeECDH[Key *ecdh.PublicKey | *ecdh.PrivateKey](key Key) (*ECDHPayload, error) {
	publicKey, ok := any(key).(*ecdh.PublicKey)

	var privateKey *ecdh.PrivateKey
	if !ok {
		privateKey = any(key).(*ecdh.PrivateKey)
		publicKey = privateKey.PublicKey()
	}

	curve := publicKey.Curve()
	payload := &ECDHPayload{Crv: fmt.Sprint(curve)}

	if _, supported := ecdhCurves[payload.Crv]; !supported {
		return nil, ErrUnsupportedCurve
	}

	point := publicKey.Bytes()
	if curve == ecdh.X25519() {
		payload.X = base64.RawURLEncoding.EncodeToString(point)
	} else {
		// Drop the 0x04 prefix and split the uncompressed point into its two coordinates.
		size := (len(point) - 1) / 2
		payload.X = base64.RawURLEncoding.EncodeToString(point[1 : 1+size])
		payload.Y = base64.RawURLEncoding.EncodeToString(point[1+size:])
	}

	if privateKey != nil {
		payload.D = base64.RawURLEncoding.EncodeToString(privateKey.Bytes())
	}

	return payload, nil
}
