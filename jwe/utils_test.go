package jwe_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/a-novel-kit/jwt/v2/jwa"
)

var errFoo = errors.New("foo error")

type fakeCEKManager struct {
	cek       []byte
	encrypted []byte
}

func (f *fakeCEKManager) SetHeader(_ context.Context, header *jwa.JWH) (*jwa.JWH, error) {
	return header, nil
}

func (f *fakeCEKManager) ComputeCEK(_ context.Context, _ *jwa.JWH) ([]byte, error) {
	return f.cek, nil
}

func (f *fakeCEKManager) EncryptCEK(_ context.Context, _ *jwa.JWH, _ []byte) ([]byte, error) {
	return f.encrypted, nil
}

type fakeCEKDecoder struct {
	cek       []byte
	encrypted []byte
}

func (f *fakeCEKDecoder) ComputeCEK(_ context.Context, _ *jwa.JWH, encKey []byte) ([]byte, error) {
	if string(encKey) != string(f.encrypted) {
		return nil, errFoo
	}

	return f.cek, nil
}

// mustDecodeBase64 decodes a base64url segment the test itself produced.
func mustDecodeBase64(t *testing.T, segment string) []byte {
	t.Helper()

	decoded, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		panic(err)
	}

	return decoded
}

// nonCanonical returns segment with an unused trailing bit set, which a lenient base64url decoder
// reads as the same bytes. It reports false when the encoded bytes leave no unused bit, as a
// multiple of 3 bytes does.
func nonCanonical(segment string) (string, bool) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

	if len(segment)%4 == 0 {
		return "", false
	}

	last := strings.IndexByte(alphabet, segment[len(segment)-1])

	return segment[:len(segment)-1] + string(alphabet[last^1]), true
}

// rfcExample is a worked JWE example of RFC 7516 Appendix A or RFC 7517 Appendix C: a compact token,
// the key or password that decrypts it, and the plaintext it carries.
type rfcExample struct {
	// JWK is the recipient's key, as the example prints it.
	JWK json.RawMessage `json:"jwk"`
	// Password is the PBES2 passphrase, set instead of JWK.
	Password string `json:"password"`

	// Segments holds the compact token's five segments, which the test joins with ".".
	Segments  []string `json:"compact"`
	Plaintext string   `json:"plaintext"`
}

// Compact returns the example's JWE compact token.
func (example rfcExample) Compact() string {
	return strings.Join(example.Segments, ".")
}

// mustLoadRFCExample returns the example testdata/rfc-examples.json holds under name.
func mustLoadRFCExample(t *testing.T, name string) rfcExample {
	t.Helper()

	raw, err := os.ReadFile("testdata/rfc-examples.json")
	if err != nil {
		panic(err)
	}

	var examples map[string]rfcExample

	err = json.Unmarshal(raw, &examples)
	if err != nil {
		panic(err)
	}

	example, ok := examples[name]
	if !ok {
		panic("no RFC example named " + name)
	}

	return example
}

// rawDeserializer hands a recipient's payload over as it is, for a plaintext that is not JSON.
func rawDeserializer(raw []byte, dst any) error {
	*dst.(*[]byte) = raw

	return nil
}
