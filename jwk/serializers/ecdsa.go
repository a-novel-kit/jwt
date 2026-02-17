package serializers

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
)

// ECPayload wraps a ECDSA key in a JWKCommon format.
type ECPayload struct {
	// Crv (curve) parameter.
	//
	// https://datatracker.ietf.org/doc/html/rfc7518#section-6.2.1.1
	//
	// The "crv" (curve) parameter identifies the cryptographic curve used
	// with the key. Curve values from [DSS] used by this specification
	// are:
	//
	// o "P-256"
	// o "P-384"
	// o "P-521"
	//
	// These values are registered in the IANA "JSON Web CEK Elliptic Curve"
	// registry defined in Section 7.6. Additional "crv" values can be
	// registered by other specifications. Specifications registering
	// additional curves must define what parameters are used to represent
	// keys for the curves registered. The "crv" value is a case-sensitive
	// string.
	//
	// SEC1 [SEC1] point compression is not supported for any of these three
	// curves.
	Crv string `json:"crv"`
	// X coordinate parameter.
	//
	// https://datatracker.ietf.org/doc/html/rfc7518#section-6.2.1.2
	//
	// The "x" (x coordinate) parameter contains the x coordinate for the
	// Elliptic Curve point. It is represented as the base64url encoding of
	// the octet string representation of the coordinate, as defined in
	// Section 2.3.5 of SEC1 [SEC1]. The length of this octet string MUST
	// be the full size of a coordinate for the curve specified in the "crv"
	// parameter. For example, if the value of "crv" is "P-521", the octet
	// string must be 66 octets long.
	X string `json:"x"`
	// Y coordinate parameter.
	//
	// https://datatracker.ietf.org/doc/html/rfc7518#section-6.2.1.3
	//
	// The "y" (y coordinate) parameter contains the y coordinate for the
	// Elliptic Curve point. It is represented as the base64url encoding of
	// the octet string representation of the coordinate, as defined in
	// Section 2.3.5 of SEC1 [SEC1]. The length of this octet string MUST
	// be the full size of a coordinate for the curve specified in the "crv"
	// parameter. For example, if the value of "crv" is "P-521", the octet
	// string must be 66 octets long.
	Y string `json:"y"`

	// PRIVATE KEY.

	// D (ECC private key) parameter.
	//
	// https://datatracker.ietf.org/doc/html/rfc7518#section-6.2.2.1
	//
	// The "d" (ECC private key) parameter contains the Elliptic Curve
	// private key value. It is represented as the base64url encoding of
	// the octet string representation of the private key value, as defined
	// in Section 2.3.7 of SEC1 [SEC1]. The length of this octet string
	// MUST be ceiling(log-base-2(n)/8) octets (where n is the order of the
	// curve).
	D string `json:"d,omitempty"`
}

// ---------------------------------------------------------------------------------------------------------------------
// Imported from go internal package.

// pointFromAffine is used to convert the PublicKey to a nistec SetBytes input.
func pointFromAffine(curve elliptic.Curve, x, y *big.Int) ([]byte, error) {
	bitSize := curve.Params().BitSize
	// Reject values that would not get correctly encoded.
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

// pointToAffine is used to convert a nistec Bytes encoding to a PublicKey.
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

// DecodeEC takes the representation of a ECPayload and computes the key it contains.
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

// EncodeEC takes a key and create a ECPayload representation of it.
func EncodeEC[Key *ecdsa.PublicKey | *ecdsa.PrivateKey](key Key) (*ECPayload, error) {
	payload := new(ECPayload)

	pubKey, ok := any(key).(*ecdsa.PublicKey)
	if ok {
		x, y, crv, err := parsePublicKeyParams(pubKey)
		if err != nil {
			return nil, fmt.Errorf("parse public key params: %w", err)
		}

		payload.Crv = crv.Params().Name
		payload.X = base64.RawURLEncoding.EncodeToString(x.Bytes())
		payload.Y = base64.RawURLEncoding.EncodeToString(y.Bytes())

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
	payload.X = base64.RawURLEncoding.EncodeToString(x.Bytes())
	payload.Y = base64.RawURLEncoding.EncodeToString(y.Bytes())
	payload.D = base64.RawURLEncoding.EncodeToString(privKeyBytes)

	return payload, nil
}
