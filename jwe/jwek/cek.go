package jwek

import (
	"crypto/rand"
	"fmt"

	"github.com/a-novel-kit/jwt/v2"
	"github.com/a-novel-kit/jwt/v2/jwa"
)

// cekSizes holds the content encryption key length, in bytes, each "enc" algorithm consumes.
// An AES-CBC-HMAC key carries both its MAC and encryption halves. It lists the algorithms the
// jwe package implements; an encryption plugin for another "enc" needs an entry here before the
// wrapping and agreement-with-wrapping managers can draw keys for it.
var cekSizes = map[jwa.Enc]int{
	jwa.A128CBC: 32,
	jwa.A192CBC: 48,
	jwa.A256CBC: 64,
	jwa.A128GCM: 16,
	jwa.A192GCM: 24,
	jwa.A256GCM: 32,
}

// newCEK returns a random content encryption key sized for the token's "enc". RFC 7516 §5.1
// requires a fresh key for every token whose key is wrapped or encrypted to the recipient.
//
// https://datatracker.ietf.org/doc/html/rfc7516#section-5.1
func newCEK(header *jwa.JWH) ([]byte, error) {
	size, ok := cekSizes[header.Enc]
	if !ok {
		return nil, fmt.Errorf("%w: no content encryption key size for enc %q", jwt.ErrUnsupportedTokenFormat, header.Enc)
	}

	cek := make([]byte, size)

	_, err := rand.Read(cek)
	if err != nil {
		return nil, fmt.Errorf("generate cek: %w", err)
	}

	return cek, nil
}
