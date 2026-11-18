package serializers_test

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt/v2/jwk/serializers"
)

func TestOct(t *testing.T) {
	t.Parallel()

	key := make([]byte, 2048)
	_, _ = rand.Read(key) // never fails: it crashes the program instead

	payload := serializers.EncodeOct(key)

	decodedKey, err := serializers.DecodeOct(payload)
	require.NoError(t, err)
	require.Equal(t, key, decodedKey)
}
