package serializers

import (
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
)

// An RSAOtherPrime describes a third or later prime factor of an RSA private key built from more than two primes,
// together with the CRT values derived from it. Values are Base64urlUInt-encoded.
//
// https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.2.7
type RSAOtherPrime struct {
	// R is the prime factor.
	R string `json:"r"`
	// D is the factor's CRT exponent.
	D string `json:"d"`
	// T is the factor's CRT coefficient.
	T string `json:"t"`
}

// An RSAPayload wraps an RSA key in a JWKCommon format. Every numeric field is Base64urlUInt-encoded, following
// RFC 7518 §6.3.
type RSAPayload struct {
	// N is the key modulus.
	//
	// https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.1.1
	N string `json:"n"`
	// E is the public exponent. For example, 65537 encodes as "AQAB".
	//
	// https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.1.2
	E string `json:"e"`

	// D is the private exponent, set only for private keys.
	//
	// https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.2.1
	D string `json:"d,omitempty"`

	// P is the first prime factor.
	//
	// https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.2.2
	P string `json:"p,omitempty"`
	// Q is the second prime factor.
	//
	// https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.2.3
	Q string `json:"q,omitempty"`

	// DP is the first factor CRT exponent.
	//
	// https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.2.4
	DP string `json:"dp,omitempty"`
	// DQ is the second factor CRT exponent.
	//
	// https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.2.5
	DQ string `json:"dq,omitempty"`
	// QI is the first CRT coefficient.
	//
	// https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.2.6
	QI string `json:"qi,omitempty"`

	// Oth carries the remaining prime factors when the key was built from more than two primes; it is omitted for
	// the usual two-prime key.
	//
	// https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.2.7
	Oth []RSAOtherPrime `json:"oth,omitempty"`
}

// DecodeRSA reconstructs the RSA key carried by an RSAPayload, returning the private key when the payload holds one.
func DecodeRSA(src *RSAPayload) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	n, err := base64.RawURLEncoding.DecodeString(src.N)
	if err != nil {
		return nil, nil, fmt.Errorf("decode rsa key modulus: %w", err)
	}

	e, err := base64.RawURLEncoding.DecodeString(src.E)
	if err != nil {
		return nil, nil, fmt.Errorf("decode rsa key exponent: %w", err)
	}

	keyPub := &rsa.PublicKey{
		N: new(big.Int).SetBytes(n),
		E: int(new(big.Int).SetBytes(e).Int64()),
	}

	if src.D == "" {
		return nil, keyPub, nil
	}

	d, err := base64.RawURLEncoding.DecodeString(src.D)
	if err != nil {
		return nil, nil, fmt.Errorf("decode rsa private key private exponent: %w", err)
	}

	p, err := base64.RawURLEncoding.DecodeString(src.P)
	if err != nil {
		return nil, nil, fmt.Errorf("decode rsa private key first prime factor: %w", err)
	}

	q, err := base64.RawURLEncoding.DecodeString(src.Q)
	if err != nil {
		return nil, nil, fmt.Errorf("decode rsa private key second prime factor: %w", err)
	}

	dp, err := base64.RawURLEncoding.DecodeString(src.DP)
	if err != nil {
		return nil, nil, fmt.Errorf("decode rsa private key first factor CRT exponent: %w", err)
	}

	dq, err := base64.RawURLEncoding.DecodeString(src.DQ)
	if err != nil {
		return nil, nil, fmt.Errorf("decode rsa private key second factor CRT exponent: %w", err)
	}

	qi, err := base64.RawURLEncoding.DecodeString(src.QI)
	if err != nil {
		return nil, nil, fmt.Errorf("decode rsa private key first CRT coefficient: %w", err)
	}

	key := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: new(big.Int).SetBytes(n),
			E: int(new(big.Int).SetBytes(e).Int64()),
		},
		D: new(big.Int).SetBytes(d),
		Primes: []*big.Int{
			new(big.Int).SetBytes(p),
			new(big.Int).SetBytes(q),
		},
		Precomputed: rsa.PrecomputedValues{
			Dp:   new(big.Int).SetBytes(dp),
			Dq:   new(big.Int).SetBytes(dq),
			Qinv: new(big.Int).SetBytes(qi),
		},
	}

	if len(src.Oth) > 0 {
		key.Precomputed.CRTValues = make([]rsa.CRTValue, len(src.Oth)+2) //nolint:staticcheck

		key.Precomputed.CRTValues[0] = rsa.CRTValue{ //nolint:staticcheck
			Exp:   new(big.Int).SetBytes(dp),
			Coeff: new(big.Int).SetBytes(qi),
		}

		key.Precomputed.CRTValues[1] = rsa.CRTValue{ //nolint:staticcheck
			Exp:   new(big.Int).SetBytes(dq),
			Coeff: new(big.Int).SetBytes(qi),
		}

		for i, oth := range src.Oth {
			OR, err := base64.RawURLEncoding.DecodeString(oth.R)
			if err != nil {
				return nil, nil, fmt.Errorf("decode rsa private key other prime factor %d: %w", i, err)
			}

			OD, err := base64.RawURLEncoding.DecodeString(oth.D)
			if err != nil {
				return nil, nil, fmt.Errorf("decode rsa private key other prime factor %d CRT exponent: %w", i, err)
			}

			OT, err := base64.RawURLEncoding.DecodeString(oth.T)
			if err != nil {
				return nil, nil, fmt.Errorf("decode rsa private key other prime factor %d CRT coefficient: %w", i, err)
			}

			key.Precomputed.CRTValues[i+2] = rsa.CRTValue{ //nolint:staticcheck
				R:     new(big.Int).SetBytes(OR),
				Exp:   new(big.Int).SetBytes(OD),
				Coeff: new(big.Int).SetBytes(OT),
			}
		}
	}

	return key, keyPub, nil
}

// EncodeRSA builds the RSAPayload representation of an RSA public or private key.
func EncodeRSA[Key *rsa.PublicKey | *rsa.PrivateKey](key Key) *RSAPayload {
	payload := new(RSAPayload)

	pubKey, ok := any(key).(*rsa.PublicKey)
	if ok {
		payload.N = base64.RawURLEncoding.EncodeToString(pubKey.N.Bytes())
		payload.E = base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pubKey.E)).Bytes())

		return payload
	}

	privKey := any(key).(*rsa.PrivateKey)

	privKey.Precompute()

	payload.N = base64.RawURLEncoding.EncodeToString(privKey.N.Bytes())
	payload.E = base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privKey.E)).Bytes())

	payload.D = base64.RawURLEncoding.EncodeToString(privKey.D.Bytes())

	payload.P = base64.RawURLEncoding.EncodeToString(privKey.Primes[0].Bytes())
	payload.Q = base64.RawURLEncoding.EncodeToString(privKey.Primes[1].Bytes())

	payload.DP = base64.RawURLEncoding.EncodeToString(privKey.Precomputed.Dp.Bytes())
	payload.DQ = base64.RawURLEncoding.EncodeToString(privKey.Precomputed.Dq.Bytes())
	payload.QI = base64.RawURLEncoding.EncodeToString(privKey.Precomputed.Qinv.Bytes())

	if len(privKey.Precomputed.CRTValues) > 0 { //nolint:staticcheck
		payload.Oth = make([]RSAOtherPrime, len(privKey.Precomputed.CRTValues)-2) //nolint:staticcheck

		for i, crt := range privKey.Precomputed.CRTValues[2:] { //nolint:staticcheck
			payload.Oth[i] = RSAOtherPrime{
				R: base64.RawURLEncoding.EncodeToString(crt.R.Bytes()),
				D: base64.RawURLEncoding.EncodeToString(crt.Exp.Bytes()),
				T: base64.RawURLEncoding.EncodeToString(crt.Coeff.Bytes()),
			}
		}
	}

	return payload
}
