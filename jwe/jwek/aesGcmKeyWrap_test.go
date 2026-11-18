package jwek_test

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt/v2"
	"github.com/a-novel-kit/jwt/v2/jwa"
	"github.com/a-novel-kit/jwt/v2/jwe/jwek"
)

func TestAESGCMKWDecoder(t *testing.T) {
	t.Parallel()

	wrapKey := randomKey(jwek.A128GCMKW.KeyLen)

	manager := jwek.NewAESGCMKWManager(&jwek.AESGCMKWManagerConfig{WrapKey: wrapKey}, jwek.A128GCMKW)
	decoder := jwek.NewAESGCMKWDecoder(&jwek.AESGCMKWDecoderConfig{WrapKey: wrapKey}, jwek.A128GCMKW)

	header, err := manager.SetHeader(t.Context(), &jwa.JWH{JWHCommon: jwa.JWHCommon{Enc: jwa.A128GCM}})
	require.NoError(t, err)

	cek, err := manager.ComputeCEK(t.Context(), header)
	require.NoError(t, err)

	encryptedKey, err := manager.EncryptCEK(t.Context(), header, cek)
	require.NoError(t, err)

	short := base64.RawURLEncoding.EncodeToString([]byte("short"))

	// The IV and tag come from the token, and AES-GCM panics on a nonce of the wrong length.
	testCases := []struct {
		name string

		malform func(common *jwa.JWHCommon)
	}{
		{name: "Error/MalformedIV", malform: func(common *jwa.JWHCommon) { common.IV = "!!!" }},
		{name: "Error/MalformedTag", malform: func(common *jwa.JWHCommon) { common.Tag = "!!!" }},
		{name: "Error/ShortIV", malform: func(common *jwa.JWHCommon) { common.IV = short }},
		{name: "Error/ShortTag", malform: func(common *jwa.JWHCommon) { common.Tag = short }},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			common := header.JWHCommon
			testCase.malform(&common)

			_, err := decoder.ComputeCEK(t.Context(), &jwa.JWH{JWHCommon: common}, encryptedKey)
			require.ErrorIs(t, err, jwt.ErrUnsupportedTokenFormat)
		})
	}
}
