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

// An RSAPayload holds the key members of an "RSA" JSON Web Key. Every numeric field is
// Base64urlUInt-encoded, following RFC 7518 §6.3.
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

	// Oth carries the remaining prime factors of a key built from more than two primes. The usual
	// two-prime key omits it.
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

	// crypto/rsa derives the CRT values of the third and later primes itself. Only their factors are read.
	for i, oth := range src.Oth {
		prime, err := base64.RawURLEncoding.DecodeString(oth.R)
		if err != nil {
			return nil, nil, fmt.Errorf("decode rsa private key other prime factor %d: %w", i, err)
		}

		key.Primes = append(key.Primes, new(big.Int).SetBytes(prime))
	}

	return key, keyPub, nil
}

// EncodeRSA builds the RSAPayload representation of an RSA public or private key.
func EncodeRSA[Key *rsa.PublicKey | *rsa.PrivateKey](key Key) *RSAPayload {
	pubKey, ok := any(key).(*rsa.PublicKey)
	if ok {
		return &RSAPayload{
			N: base64.RawURLEncoding.EncodeToString(pubKey.N.Bytes()),
			E: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pubKey.E)).Bytes()),
		}
	}

	privKey := any(key).(*rsa.PrivateKey)

	privKey.Precompute()

	payload := &RSAPayload{
		N:  base64.RawURLEncoding.EncodeToString(privKey.N.Bytes()),
		E:  base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privKey.E)).Bytes()),
		D:  base64.RawURLEncoding.EncodeToString(privKey.D.Bytes()),
		P:  base64.RawURLEncoding.EncodeToString(privKey.Primes[0].Bytes()),
		Q:  base64.RawURLEncoding.EncodeToString(privKey.Primes[1].Bytes()),
		DP: base64.RawURLEncoding.EncodeToString(privKey.Precomputed.Dp.Bytes()),
		DQ: base64.RawURLEncoding.EncodeToString(privKey.Precomputed.Dq.Bytes()),
		QI: base64.RawURLEncoding.EncodeToString(privKey.Precomputed.Qinv.Bytes()),
	}

	// Precompute keeps one CRTValues entry per prime after the second, in the order of Primes.
	for i, prime := range privKey.Primes[2:] {
		crt := privKey.Precomputed.CRTValues[i] //nolint:staticcheck

		payload.Oth = append(payload.Oth, RSAOtherPrime{
			R: base64.RawURLEncoding.EncodeToString(prime.Bytes()),
			D: base64.RawURLEncoding.EncodeToString(crt.Exp.Bytes()),
			T: base64.RawURLEncoding.EncodeToString(crt.Coeff.Bytes()),
		})
	}

	return payload
}
