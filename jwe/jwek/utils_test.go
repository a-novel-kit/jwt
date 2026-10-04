package jwek_test

import (
	"encoding/base64"
	"testing"
)

// mustDecode decodes a base64url segment of a test vector.
func mustDecode(t *testing.T, segment string) []byte {
	t.Helper()

	decoded, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		panic(err)
	}

	return decoded
}
