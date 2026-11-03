package serializers

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
)

// An ECPayload holds the key members of an "EC" JSON Web Key carrying an ECDSA key.
type ECPayload struct {
	// Crv is the case-sensitive JWK name of the curve the key lives on. DecodeEC supports "P-256",
	// "P-384", and "P-521", and returns ErrUnsupportedCurve for any other value.
	//
	// https://datatracker.ietf.org/doc/html/rfc7518#section-6.2.1.1
	Crv string `json:"crv"`
	// X is the base64url-encoded x coordinate of the curve point.
	//
	// https://datatracker.ietf.org/doc/html/rfc7518#section-6.2.1.2
	X string `json:"x"`
	// Y is the base64url-encoded y coordinate of the curve point.
	//
	// https://datatracker.ietf.org/doc/html/rfc7518#section-6.2.1.3
	Y string `json:"y"`

	// D is the base64url-encoded private key value, set only for private keys.
	//
	// https://datatracker.ietf.org/doc/html/rfc7518#section-6.2.2.1
	D string `json:"d,omitempty"`
}

// ErrInvalidECKey is returned when a decoded ECDSA key has a coordinate shorter or longer than its
// curve requires, or a private key that does not match its public point.
var ErrInvalidECKey = errors.New("invalid ECDSA key")

// DecodeEC reconstructs the ECDSA key carried by an ECPayload, returning the private key when the payload holds one.
func DecodeEC(src *ECPayload) (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	var curve elliptic.Curve

	switch src.Crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, nil, fmt.Errorf("%w: %s", ErrUnsupportedCurve, src.Crv)
	}

	x, err := base64.RawURLEncoding.DecodeString(src.X)
	if err != nil {
		return nil, nil, fmt.Errorf("decode x: %w", err)
	}

	y, err := base64.RawURLEncoding.DecodeString(src.Y)
	if err != nil {
		return nil, nil, fmt.Errorf("decode y: %w", err)
	}

	// RFC 7518 §6.2.1.2 and §6.2.1.3: each coordinate is the full size of a coordinate on the curve,
	// leading zero octets included.
	size := (curve.Params().BitSize + 7) / 8
	if len(x) != size || len(y) != size {
		return nil, nil, fmt.Errorf("%w: coordinates must be %d octets each", ErrInvalidECKey, size)
	}

	keyPub, err := ecdsa.ParseUncompressedPublicKey(curve, slices.Concat([]byte{4}, x, y))
	if err != nil {
		return nil, nil, fmt.Errorf("parse uncompressed public key: %w", err)
	}

	if src.D == "" {
		return nil, keyPub, nil
	}

	d, err := base64.RawURLEncoding.DecodeString(src.D)
	if err != nil {
		return nil, nil, fmt.Errorf("decode d: %w", err)
	}

	keyPriv, err := ecdsa.ParseRawPrivateKey(curve, d)
	if err != nil {
		return nil, nil, fmt.Errorf("parse raw private key: %w", err)
	}

	// A signature made with a private key that does not match "x" and "y" never verifies against them.
	if !keyPriv.PublicKey.Equal(keyPub) {
		return nil, nil, fmt.Errorf("%w: private key does not match public key", ErrInvalidECKey)
	}

	return keyPriv, keyPub, nil
}

// EncodeEC builds the ECPayload representation of an ECDSA public or private key.
func EncodeEC[Key *ecdsa.PublicKey | *ecdsa.PrivateKey](key Key) (*ECPayload, error) {
	publicKey, ok := any(key).(*ecdsa.PublicKey)

	var privateKey *ecdsa.PrivateKey
	if !ok {
		privateKey = any(key).(*ecdsa.PrivateKey)
		publicKey = &privateKey.PublicKey
	}

	// Bytes returns the uncompressed point 0x04 || X || Y, each coordinate at the curve's full octet
	// length, as RFC 7518 §6.2.1.2 and §6.2.1.3 require. big.Int.Bytes would drop leading zero bytes.
	point, err := publicKey.Bytes()
	if err != nil {
		return nil, fmt.Errorf("serialize public key: %w", err)
	}

	size := (len(point) - 1) / 2

	payload := &ECPayload{
		Crv: publicKey.Curve.Params().Name,
		X:   base64.RawURLEncoding.EncodeToString(point[1 : 1+size]),
		Y:   base64.RawURLEncoding.EncodeToString(point[1+size:]),
	}

	if privateKey == nil {
		return payload, nil
	}

	privateKeyBytes, err := privateKey.Bytes()
	if err != nil {
		return nil, fmt.Errorf("serialize private key: %w", err)
	}

	// PrivateKey.Bytes is already fixed-length per SEC 1 §2.3.7, which is what RFC 7518 §6.2.2.1 wants.
	payload.D = base64.RawURLEncoding.EncodeToString(privateKeyBytes)

	return payload, nil
}
