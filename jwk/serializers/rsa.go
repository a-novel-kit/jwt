package serializers

import (
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
)

type RSAOtherPrime struct {
	// R prime factor.
	//
	// https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.2.7.1
	//
	// The "r" (prime factor) parameter within an "oth" array member
	// represents the value of a subsequent prime factor. It is represented
	// as a Base64urlUInt-encoded value.
	R string `json:"r"`
	// D factor CRT exponent.
	//
	// https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.2.7.2
	//
	// The "d" (factor CRT exponent) parameter within an "oth" array member
	// represents the CRT exponent of the corresponding prime factor. It is
	// represented as a Base64urlUInt-encoded value.
	D string `json:"d"`
	// T factor CRT coefficient.
	//
	// https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.2.7.3
	//
	// The "t" (factor CRT coefficient) parameter within an "oth" array
	// member represents the CRT coefficient of the corresponding prime
	// factor. It is represented as a Base64urlUInt-encoded value.
	T string `json:"t"`
}

// RSAPayload wraps a RSA key in a JWKCommon format.
type RSAPayload struct {
	// N modulus of the key.
	//
	// https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.1.1
	//
	// The "n" (modulus) parameter contains the modulus value for the RSA
	// public key. It is represented as a Base64urlUInt-encoded value.
	//
	// Note that implementers have found that some cryptographic libraries
	// prefix an extra zero-valued octet to the modulus representations they
	// return, for instance, returning 257 octets for a 2048-bit key, rather
	// than 256. Implementations using such libraries will need to take
	// care to omit the extra octet from the base64url-encoded
	// representation.
	N string `json:"n"`
	// E exponent of the key.
	//
	// https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.1.2
	//
	// The "e" (exponent) parameter contains the exponent value for the RSA
	// public key. It is represented as a Base64urlUInt-encoded value.
	//
	// For instance, when representing the value 65537, the octet sequence
	// to be base64url-encoded MUST consist of the three octets [1, 0, 1];
	// the resulting representation for this value is "AQAB".
	E string `json:"e"`

	// PRIVATE KEY.

	// D private exponent of the key.
	//
	// https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.2.1
	//
	// The "d" (private exponent) parameter contains the private exponent
	// value for the RSA private key. It is represented as a Base64urlUInt-
	// encoded value.
	D string `json:"d,omitempty"`

	// P first prime factor of the key.
	//
	// https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.2.2
	//
	// The "p" (first prime factor) parameter contains the first prime
	// factor. It is represented as a Base64urlUInt-encoded value.
	P string `json:"p,omitempty"`
	// Q second prime factor of the key.
	//
	// https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.2.3
	//
	// The "q" (second prime factor) parameter contains the second prime
	// factor. It is represented as a Base64urlUInt-encoded value.
	Q string `json:"q,omitempty"`

	// DP first factor CRT exponent.
	//
	//https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.2.4
	//
	// The "dp" (first factor CRT exponent) parameter contains the Chinese
	// Remainder Theorem (CRT) exponent of the first factor. It is
	// represented as a Base64urlUInt-encoded value.
	DP string `json:"dp,omitempty"`
	// DQ second factor CRT exponent.
	//
	// https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.2.5
	//
	// The "dq" (second factor CRT exponent) parameter contains the CRT
	// exponent of the second factor. It is represented as a Base64urlUInt-
	// encoded value.
	DQ string `json:"dq,omitempty"`
	// QI first CRT coefficient.
	//
	// https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.2.6
	//
	// The "qi" (first CRT coefficient) parameter contains the CRT
	// coefficient of the second factor. It is represented as a
	// Base64urlUInt-encoded value.
	QI string `json:"qi,omitempty"`

	// Oth other primes info.
	//
	// https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.2.7
	//
	// The "oth" (other primes info) parameter contains an array of
	// information about any third and subsequent primes, should they exist.
	// When only two primes have been used (the normal case), this parameter
	// MUST be omitted. When three or more primes have been used, the
	// number of array elements MUST be the number of primes used minus two.
	// For more information on this case, see the description of the
	// OtherPrimeInfo parameters in Appendix A.1.2 of RFC 3447 [RFC3447],
	// upon which the following parameters are modeled. If the consumer of
	// a JWKCommon does not support private keys with more than two primes and it
	// encounters a private key that includes the "oth" parameter, then it
	// MUST NOT use the key. Each array element MUST be an object with the
	// following members.
	Oth []RSAOtherPrime `json:"oth,omitempty"`
}

// DecodeRSA takes the representation of a RSAPayload and computes the key it contains.
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

// EncodeRSA takes a key and create a RSAPayload representation of it.
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
