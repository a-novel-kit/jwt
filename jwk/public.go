package jwk

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/a-novel-kit/jwt/v2/jwa"
)

// ErrPrivateKeyMaterial reports a key carrying members that must not leave the
// signer: the RSA private exponent and its CRT factors, the EC and OKP private
// scalar, or the octet sequence a symmetric key consists of.
var ErrPrivateKeyMaterial = errors.New("key carries private material")

// privateMembers are the JWK members RFC 7518 §6 defines as private, across
// every key type. RSA carries the most; EC and OKP carry only "d"; a symmetric
// key is nothing but its secret, which is why Public refuses one outright.
//
// The names are a closed set fixed by the RFC, so a new key type is the only
// thing that can add to it.
//
// https://datatracker.ietf.org/doc/html/rfc7518#section-6
var privateMembers = []string{
	"d",   // RSA private exponent; EC and OKP private scalar
	"p",   // RSA first prime factor
	"q",   // RSA second prime factor
	"dp",  // RSA first factor CRT exponent
	"dq",  // RSA second factor CRT exponent
	"qi",  // RSA first CRT coefficient
	"oth", // RSA other primes, each with its own r, d and t
	"k",   // symmetric key value
}

// HasPrivateMaterial reports whether key carries any member that must stay with
// the signer. A symmetric key always does.
func HasPrivateMaterial(key *jwa.JWK) (bool, error) {
	if key == nil {
		return false, nil
	}

	if key.KTY == jwa.KTYOct {
		return true, nil
	}

	members, err := payloadMembers(key)
	if err != nil {
		return false, err
	}

	for _, name := range privateMembers {
		if _, ok := members[name]; ok {
			return true, nil
		}
	}

	return false, nil
}

// Public returns key with every private member removed, leaving the half a
// recipient needs to verify. The original is not modified.
//
// A symmetric key has no public half — its single member is the secret — so one
// yields ErrPrivateKeyMaterial rather than an emptied key that would look
// publishable.
func Public(key *jwa.JWK) (*jwa.JWK, error) {
	if key == nil {
		return nil, nil
	}

	if key.KTY == jwa.KTYOct {
		return nil, fmt.Errorf("%w: a %s key is its secret and has no public half", ErrPrivateKeyMaterial, key.KTY)
	}

	members, err := payloadMembers(key)
	if err != nil {
		return nil, err
	}

	for _, name := range privateMembers {
		delete(members, name)
	}

	payload, err := json.Marshal(members)
	if err != nil {
		return nil, fmt.Errorf("(Public) serialize payload: %w", err)
	}

	out := *key
	out.Payload = payload

	return &out, nil
}

// payloadMembers decodes a key's type-specific members. An absent payload
// decodes to an empty set, so a key holding only common parameters is read as
// carrying nothing private.
func payloadMembers(key *jwa.JWK) (map[string]json.RawMessage, error) {
	members := map[string]json.RawMessage{}

	if len(key.Payload) == 0 {
		return members, nil
	}

	err := json.Unmarshal(key.Payload, &members)
	if err != nil {
		return nil, fmt.Errorf("(jwk) decode key payload: %w", err)
	}

	return members, nil
}
