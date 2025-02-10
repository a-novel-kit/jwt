package serializers_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt/jwk/generators"
	"github.com/a-novel-kit/jwt/jwk/serializers"
)

func TestOct(t *testing.T) {
	t.Parallel()

	key, err := generators.NewOct(2048)
	require.NoError(t, err)

	payload := serializers.EncodeOct(key)

	decodedKey, err := serializers.DecodeOct(payload)
	require.NoError(t, err)
	require.Equal(t, key, decodedKey)
}
