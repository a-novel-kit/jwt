package serializers

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
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

// ErrInvalidECKey is returned when the private key of a decoded ECDSA key does not match its public
// point.
var ErrInvalidECKey = errors.New("invalid ECDSA key")

// ---------------------------------------------------------------------------------------------------------------------
// Reimplemented from crypto/ecdsa internals, which the standard library does not export.

// pointFromAffine encodes affine coordinates into the uncompressed point bytes
// that ecdsa.ParseUncompressedPublicKey expects.
func pointFromAffine(curve elliptic.Curve, x, y *big.Int) ([]byte, error) {
	bitSize := curve.Params().BitSize
	// Reject values that do not encode correctly.
	if x.Sign() < 0 || y.Sign() < 0 {
		return nil, errors.New("negative coordinate")
	}

	if x.BitLen() > bitSize || y.BitLen() > bitSize {
		return nil, errors.New("overflowing coordinate")
	}
	// Encode the coordinates and let ecdsa.ParseUncompressedPublicKey reject invalid points.
	byteLen := (bitSize + 7) / 8
	buf := make([]byte, 1+2*byteLen)
	buf[0] = 4 // uncompressed point
	x.FillBytes(buf[1 : 1+byteLen])
	y.FillBytes(buf[1+byteLen : 1+2*byteLen])

	return buf, nil
}

// ---------------------------------------------------------------------------------------------------------------------

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

	rawKey, err := pointFromAffine(curve, new(big.Int).SetBytes(x), new(big.Int).SetBytes(y))
	if err != nil {
		return nil, nil, fmt.Errorf("parse public key params: %w", err)
	}

	keyPub, err := ecdsa.ParseUncompressedPublicKey(curve, rawKey)
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
