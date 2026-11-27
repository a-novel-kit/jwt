package jwk

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/a-novel-kit/jwt/v2/jwa"
)

// ErrNoThumbprint is returned by Thumbprint for a key it cannot hash. The key is nil, its type is
// unknown, or a member its type requires is missing, empty, or not a string that JSON writes without
// escaping. The message names the member at fault and quotes no key material.
var ErrNoThumbprint = errors.New("key has no thumbprint")

// thumbprintMembers lists the members each key type requires, in the lexicographic order of the hash
// input. RFC 7638 §3.2 names them for RSA, EC and symmetric keys, RFC 8037 §2 for OKP keys, and
// RFC 9964 §6 for AKP keys.
//
//nolint:goconst // Each list spells its members out as its RFC orders them.
var thumbprintMembers = map[jwa.KTY][]string{
	jwa.KTYRSA: {"e", "kty", "n"},
	jwa.KTYEC:  {"crv", "kty", "x", "y"},
	jwa.KTYOct: {"k", "kty"},
	jwa.KTYOKP: {"crv", "kty", "x"},
	jwa.KTYAKP: {"alg", "kty", "pub"},
}

// Thumbprint returns the JWK thumbprint of key under SHA-256 (RFC 7638 §3), encoded as base64url
// without padding. The hash covers only the members the key's type requires, so the thumbprint
// identifies the key whatever its other members say, and a private key shares the thumbprint of its
// public half. A key that lacks one of those members yields [ErrNoThumbprint].
//
// The required members are those of RFC 7638 §3.2, of RFC 8037 §2 for an OKP key, and of
// RFC 9964 §6 for an AKP key. Each value is hashed as the key carries it (RFC 7638 §3.3), with no
// check that it encodes a valid key. The thumbprint of a symmetric key is a hash of its secret.
// RFC 7638 §7 advises keeping it from parties that do not hold the key.
func Thumbprint(key *jwa.JWK) (string, error) {
	if key == nil {
		return "", fmt.Errorf("%w: key is nil", ErrNoThumbprint)
	}

	names, ok := thumbprintMembers[key.KTY]
	if !ok {
		return "", fmt.Errorf("%w: unknown key type %q", ErrNoThumbprint, key.KTY)
	}

	members, err := payloadMembers(key)
	if err != nil {
		// The decoding error can quote a character of the payload, so the message leaves it out.
		return "", fmt.Errorf("%w: payload is not a JSON object", ErrNoThumbprint)
	}

	// RFC 7638 §3 hashes one JSON object, written without whitespace.
	hashInput := []byte{'{'}

	for i, name := range names {
		value, err := thumbprintValue(key, members, name)
		if err != nil {
			return "", err
		}

		if i > 0 {
			hashInput = append(hashInput, ',')
		}

		hashInput = fmt.Appendf(hashInput, `"%s":"%s"`, name, value)
	}

	hashInput = append(hashInput, '}')

	sum := sha256.Sum256(hashInput)

	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// thumbprintValue returns the string key carries for the required member name. The common parameters
// hold "kty" and "alg", and the payload holds every other member.
func thumbprintValue(key *jwa.JWK, members map[string]json.RawMessage, name string) (string, error) {
	var value string

	switch name {
	case "kty":
		value = key.KTY.String()
	case "alg":
		value = key.Alg.String()
	default:
		// Decoding leaves value empty for a member that is absent, null or not a string. The check
		// below reports all three, so the decoding error is dropped.
		_ = json.Unmarshal(members[name], &value)
	}

	if value == "" {
		return "", fmt.Errorf("%w: member %q is missing or is not a string", ErrNoThumbprint, name)
	}

	// RFC 7638 §3.3 writes each value unescaped, and defines no thumbprint for a value holding a
	// character that JSON has to escape.
	if strings.ContainsFunc(value, func(r rune) bool { return r < ' ' || r == '"' || r == '\\' }) {
		return "", fmt.Errorf("%w: member %q holds a character JSON escapes", ErrNoThumbprint, name)
	}

	return value, nil
}
