package serializers

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
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

	keyPub := &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(x),
		Y:     new(big.Int).SetBytes(y),
	}

	if src.D == "" {
		return nil, keyPub, nil
	}

	d, err := base64.RawURLEncoding.DecodeString(src.D)
	if err != nil {
		return nil, nil, fmt.Errorf("decode d: %w", err)
	}

	keyPriv := &ecdsa.PrivateKey{
		PublicKey: *keyPub,
		D:         new(big.Int).SetBytes(d),
	}

	return keyPriv, keyPub, nil
}

// EncodeEC takes a key and create a ECPayload representation of it.
func EncodeEC[Key *ecdsa.PublicKey | *ecdsa.PrivateKey](key Key) (*ECPayload, error) {
	payload := new(ECPayload)

	pubKey, ok := any(key).(*ecdsa.PublicKey)
	if ok {
		payload.Crv = pubKey.Curve.Params().Name
		payload.X = base64.RawURLEncoding.EncodeToString(pubKey.X.Bytes())
		payload.Y = base64.RawURLEncoding.EncodeToString(pubKey.Y.Bytes())

		return payload, nil
	}

	privKey := any(key).(*ecdsa.PrivateKey)

	payload.Crv = privKey.PublicKey.Curve.Params().Name
	payload.X = base64.RawURLEncoding.EncodeToString(privKey.X.Bytes())
	payload.Y = base64.RawURLEncoding.EncodeToString(privKey.Y.Bytes())
	payload.D = base64.RawURLEncoding.EncodeToString(privKey.D.Bytes())

	return payload, nil
}
