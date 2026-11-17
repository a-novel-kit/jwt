package jwek_test

import (
	"crypto"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt/v2"
	"github.com/a-novel-kit/jwt/v2/jwa"
	"github.com/a-novel-kit/jwt/v2/jwe/jwek"
)

func TestPBES2KeyEncKWManager(t *testing.T) {
	t.Parallel()

	t.Run("Success/Defaults", func(t *testing.T) {
		t.Parallel()

		// A zero SaltSize and Iterations select the defaults. rand.Read fills an empty salt without
		// error, and the decoder rejects p2c=0, so neither zero value may reach a token.
		manager := jwek.NewPBES2KeyEncKWManager(&jwek.PBES2KeyEncKWManagerConfig{Secret: "a password"}, jwek.PBES2A128KW)

		first, err := manager.SetHeader(t.Context(), &jwa.JWH{})
		require.NoError(t, err)
		require.Len(t, mustDecodeBase64(t, first.P2S), jwek.DefaultPBES2SaltSize)
		require.Equal(t, jwek.DefaultPBES2Iterations, first.P2C)

		second, err := manager.SetHeader(t.Context(), &jwa.JWH{})
		require.NoError(t, err)
		require.NotEqual(t, first.P2S, second.P2S, "each token must carry a fresh salt")
	})

	t.Run("Error/AlgSet", func(t *testing.T) {
		t.Parallel()

		manager := jwek.NewPBES2KeyEncKWManager(&jwek.PBES2KeyEncKWManagerConfig{Secret: "a password"}, jwek.PBES2A256KW)

		// SetHeader refuses to overwrite an algorithm already stamped on the header.
		_, err := manager.SetHeader(t.Context(), &jwa.JWH{JWHCommon: jwa.JWHCommon{Alg: jwa.RS256}})
		require.ErrorIs(t, err, jwt.ErrConflictingHeader)
	})

	t.Run("Error/ShortSalt", func(t *testing.T) {
		t.Parallel()

		manager := jwek.NewPBES2KeyEncKWManager(&jwek.PBES2KeyEncKWManagerConfig{
			Iterations: 1000,
			SaltSize:   7,
			Secret:     "a password",
		}, jwek.PBES2A256KW)

		header, err := manager.SetHeader(t.Context(), &jwa.JWH{JWHCommon: jwa.JWHCommon{Enc: jwa.A256GCM}})
		require.NoError(t, err)

		// RFC 7518 §4.8.1.1: a Salt Input shorter than 8 octets fails issuance.
		_, err = manager.EncryptCEK(t.Context(), header, make([]byte, 32))
		require.Error(t, err)
	})
}

func TestPBES2KeyEncKWDecoder(t *testing.T) {
	t.Parallel()

	manager := jwek.NewPBES2KeyEncKWManager(
		&jwek.PBES2KeyEncKWManagerConfig{Secret: "a password", Iterations: 1000}, jwek.PBES2A128KW,
	)
	decoder := jwek.NewPBES2KeyEncKWDecoder(&jwek.PBES2KeyEncKWDecoderConfig{Secret: "a password"}, jwek.PBES2A128KW)

	header, err := manager.SetHeader(t.Context(), &jwa.JWH{JWHCommon: jwa.JWHCommon{Enc: jwa.A256GCM}})
	require.NoError(t, err)

	cek, err := manager.ComputeCEK(t.Context(), header)
	require.NoError(t, err)

	encryptedKey, err := manager.EncryptCEK(t.Context(), header, cek)
	require.NoError(t, err)

	testCases := []struct {
		name string

		malform      func(common *jwa.JWHCommon)
		encryptedKey []byte

		expectErr error
	}{
		{
			name:         "Error/AlgMismatch",
			malform:      func(common *jwa.JWHCommon) { common.Alg = jwa.RS256 },
			encryptedKey: encryptedKey,
			expectErr:    jwt.ErrMismatchRecipientPlugin,
		},
		{
			name:      "Error/MissingEncKey",
			expectErr: jwt.ErrUnsupportedTokenFormat,
		},
		{
			name:         "Error/MalformedSalt",
			malform:      func(common *jwa.JWHCommon) { common.P2S = "!!!" },
			encryptedKey: encryptedKey,
			expectErr:    jwt.ErrUnsupportedTokenFormat,
		},
		{
			// RFC 7518 §4.8.1.1: the Salt Input holds 8 or more octets.
			name: "Error/ShortSalt",
			malform: func(common *jwa.JWHCommon) {
				common.P2S = base64.RawURLEncoding.EncodeToString([]byte("1234567"))
			},
			encryptedKey: encryptedKey,
			expectErr:    jwt.ErrUnsupportedTokenFormat,
		},
		{
			// p2c comes from the token, so a count past the cap is refused before PBKDF2 runs.
			name:         "Error/P2CTooLarge",
			malform:      func(common *jwa.JWHCommon) { common.P2C = jwek.DefaultMaxPBES2Iterations + 1 },
			encryptedKey: encryptedKey,
			expectErr:    jwt.ErrUnsupportedTokenFormat,
		},
		{
			name:         "Error/P2CZero",
			malform:      func(common *jwa.JWHCommon) { common.P2C = 0 },
			encryptedKey: encryptedKey,
			expectErr:    jwt.ErrUnsupportedTokenFormat,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			common := header.JWHCommon
			if testCase.malform != nil {
				testCase.malform(&common)
			}

			_, err := decoder.ComputeCEK(t.Context(), &jwa.JWH{JWHCommon: common}, testCase.encryptedKey)
			require.ErrorIs(t, err, testCase.expectErr)
		})
	}

	// RFC 7518 §4.8.1.1 prefixes the salt with the algorithm, so one password reused across two PBES2
	// algorithms derives unrelated wrap keys. This preset differs from PBES2A128KW by its name only.
	t.Run("Error/SaltBindsTheAlgorithm", func(t *testing.T) {
		t.Parallel()

		otherAlg := jwek.NewPBES2KeyEncKWDecoder(
			&jwek.PBES2KeyEncKWDecoderConfig{Secret: "a password"},
			jwek.PBES2KeyEncKWPreset{Alg: jwa.PBES2HS384A192KW, Hash: crypto.SHA256, KeySize: 16},
		)

		common := header.JWHCommon
		common.Alg = jwa.PBES2HS384A192KW

		_, err := otherAlg.ComputeCEK(t.Context(), &jwa.JWH{JWHCommon: common}, encryptedKey)
		require.ErrorIs(t, err, jwt.ErrTokenRejected)
	})
}
