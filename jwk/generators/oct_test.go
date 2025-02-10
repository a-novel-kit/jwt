package generators_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt/jwk/generators"
)

func TestNewOct(t *testing.T) {
	t.Parallel()

	key1, err := generators.NewOct(12)
	require.NoError(t, err)
	require.Len(t, key1, 12)

	key2, err := generators.NewOct(24)
	require.NoError(t, err)
	require.Len(t, key2, 24)
}
