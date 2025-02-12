package jwek_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt/jwa"
	"github.com/a-novel-kit/jwt/jwe/jwek"
	"github.com/a-novel-kit/jwt/jwk"
)

func TestDirectEncryption(t *testing.T) {
	t.Parallel()

	cek, err := jwk.GenerateAES(jwk.A128GCM)
	require.NoError(t, err)

	manager := jwek.NewDirectKeyManager(cek.Key())

	header, err := manager.SetHeader(t.Context(), &jwa.JWH{})
	require.NoError(t, err)

	computedCEK, err := manager.ComputeCEK(t.Context(), header)
	require.NoError(t, err)
	require.Equal(t, cek.Key(), computedCEK)

	encryptedCEK, err := manager.EncryptCEK(t.Context(), cek.Key())
	require.NoError(t, err)
	require.Nil(t, encryptedCEK)

	decoder := jwek.NewDirectKeyDecoder(&jwek.DirectKeyDecoderConfig{CEK: cek.Key()})

	decodedCEK, err := decoder.ComputeCEK(t.Context(), header, nil)
	require.NoError(t, err)
	require.Equal(t, cek.Key(), decodedCEK)
}
