package serializers

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
)

// An ECPayload wraps an ECDSA key in a JWKCommon format.
type ECPayload struct {
	// Crv is the case-sensitive JWK name of the elliptic curve the key belongs to. DecodeEC accepts the curves
	// listed in its switch; any other value returns ErrUnsupportedCurve.
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
	// Encode the coordinates and let [ecdsa.NewPublicKey] reject invalid points.
	byteLen := (bitSize + 7) / 8
	buf := make([]byte, 1+2*byteLen)
	buf[0] = 4 // uncompressed point
	x.FillBytes(buf[1 : 1+byteLen])
	y.FillBytes(buf[1+byteLen : 1+2*byteLen])

	return buf, nil
}

// pointToAffine splits uncompressed point bytes back into their affine x and y coordinates.
//
//nolint:nonamedreturns
func pointToAffine(curve elliptic.Curve, p []byte) (x, y *big.Int, err error) {
	if len(p) == 1 && p[0] == 0 {
		// This is the encoding of the point at infinity.
		return nil, nil, errors.New("ecdsa: public key point is the infinity")
	}

	byteLen := (curve.Params().BitSize + 7) / 8
	x = new(big.Int).SetBytes(p[1 : 1+byteLen])
	y = new(big.Int).SetBytes(p[1+byteLen:])

	return x, y, nil
}

// ---------------------------------------------------------------------------------------------------------------------

func parsePublicKeyParams(key *ecdsa.PublicKey) (*big.Int, *big.Int, elliptic.Curve, error) {
	raw, err := key.Bytes()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse public key params: %w", err)
	}

	crv := key.Curve

	x, y, err := pointToAffine(crv, raw)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse public key params: %w", err)
	}

	return x, y, crv, nil
}

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

	return keyPriv, keyPub, nil
}

// encodeCoordinate renders an affine coordinate at the curve's full octet length.
//
// RFC 7518 requires x and y to be "the full size of a coordinate for the curve"
// (https://datatracker.ietf.org/doc/html/rfc7518#section-6.2.1.2), while [big.Int.Bytes] drops
// leading zero bytes — which roughly one coordinate in 256 has. Spec-compliant consumers such as
// WebCrypto importKey reject the short value, and only they do: [DecodeEC] reads through
// [big.Int.SetBytes], which accepts any length.
//
// FillBytes panics on a value too large for the buffer; callers pass coordinates read off a parsed
// key, which are on the curve and therefore fit by construction.
func encodeCoordinate(curve elliptic.Curve, coordinate *big.Int) string {
	buf := make([]byte, (curve.Params().BitSize+7)/8)
	coordinate.FillBytes(buf)

	return base64.RawURLEncoding.EncodeToString(buf)
}

// EncodeEC builds the ECPayload representation of an ECDSA public or private key.
func EncodeEC[Key *ecdsa.PublicKey | *ecdsa.PrivateKey](key Key) (*ECPayload, error) {
	payload := new(ECPayload)

	pubKey, ok := any(key).(*ecdsa.PublicKey)
	if ok {
		x, y, crv, err := parsePublicKeyParams(pubKey)
		if err != nil {
			return nil, fmt.Errorf("parse public key params: %w", err)
		}

		payload.Crv = crv.Params().Name
		payload.X = encodeCoordinate(crv, x)
		payload.Y = encodeCoordinate(crv, y)

		return payload, nil
	}

	privKey, ok := any(key).(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("invalid key type: %T", key)
	}

	x, y, crv, err := parsePublicKeyParams(&privKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("parse public key params: %w", err)
	}

	privKeyBytes, err := privKey.Bytes()
	if err != nil {
		return nil, fmt.Errorf("serialize private key: %w", err)
	}

	payload.Crv = crv.Params().Name
	payload.X = encodeCoordinate(crv, x)
	payload.Y = encodeCoordinate(crv, y)
	// privKey.Bytes is already fixed-length per SEC 1 §2.3.7, which is what RFC 7518 §6.2.2.1 wants.
	payload.D = base64.RawURLEncoding.EncodeToString(privKeyBytes)

	return payload, nil
}
