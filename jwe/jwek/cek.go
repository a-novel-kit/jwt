package jwek

import (
	"context"
	"crypto/rand"
	"fmt"

	"github.com/a-novel-kit/jwt/v2"
	"github.com/a-novel-kit/jwt/v2/jwa"
	"github.com/a-novel-kit/jwt/v2/jwe"
)

// cekSizes holds the content encryption key length, in bytes, of each "enc" the jwe package
// implements, as its presets state it. An encryption plugin for another "enc" needs an entry here
// before the key managers can draw or derive a key for it.
var cekSizes = map[jwa.Enc]int{
	jwe.A128CBCHS256.Enc: jwe.A128CBCHS256.KeyLen,
	jwe.A192CBCHS384.Enc: jwe.A192CBCHS384.KeyLen,
	jwe.A256CBCHS512.Enc: jwe.A256CBCHS512.KeyLen,
	jwe.A128GCM.Enc:      jwe.A128GCM.KeyLen,
	jwe.A192GCM.Enc:      jwe.A192GCM.KeyLen,
	jwe.A256GCM.Enc:      jwe.A256GCM.KeyLen,
}

// cekSize returns the content encryption key length enc takes, in bytes.
func cekSize(enc jwa.Enc) (int, error) {
	size, ok := cekSizes[enc]
	if !ok {
		return 0, fmt.Errorf("%w: no content encryption key size for enc %q", jwt.ErrInvalidSecretKey, enc)
	}

	return size, nil
}

// freshCEK provides ComputeCEK to the key managers that wrap or encrypt a random content encryption
// key.
type freshCEK struct{}

// ComputeCEK returns a random content encryption key sized for the token's "enc". RFC 7516 §5.1
// requires a fresh key for every token whose key is wrapped or encrypted to the recipient.
//
// https://datatracker.ietf.org/doc/html/rfc7516#section-5.1
func (freshCEK) ComputeCEK(_ context.Context, header *jwa.JWH) ([]byte, error) {
	size, err := cekSize(header.Enc)
	if err != nil {
		return nil, err
	}

	cek := make([]byte, size)
	_, _ = rand.Read(cek) // never fails: it crashes the program instead

	return cek, nil
}
