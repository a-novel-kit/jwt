package jwk_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/samber/lo"
	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt/jwa"
	"github.com/a-novel-kit/jwt/jwk"
	"github.com/a-novel-kit/jwt/jwk/serializers"
)

func mustAES(t *testing.T, preset jwk.AESPreset) *jwk.Key[[]byte] {
	t.Helper()

	key, err := jwk.GenerateAES(preset)
	require.NoError(t, err)

	return key
}

func TestGenerateAES(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name   string
		preset jwk.AESPreset
	}{
		{
			name:   "A128CBC",
			preset: jwk.A128CBC,
		},
		{
			name:   "A192CBC",
			preset: jwk.A192CBC,
		},
		{
			name:   "A256CBC",
			preset: jwk.A256CBC,
		},
		{
			name:   "A128GCM",
			preset: jwk.A128GCM,
		},
		{
			name:   "A192GCM",
			preset: jwk.A192GCM,
		},
		{
			name:   "A256GCM",
			preset: jwk.A256GCM,
		},

		{
			name:   "A128KW",
			preset: jwk.A128KW,
		},
		{
			name:   "A192KW",
			preset: jwk.A192KW,
		},
		{
			name:   "A256KW",
			preset: jwk.A256KW,
		},
		{
			name:   "A128GCMKW",
			preset: jwk.A128GCMKW,
		},
		{
			name:   "A192GCMKW",
			preset: jwk.A192GCMKW,
		},
		{
			name:   "A256GCMKW",
			preset: jwk.A256GCMKW,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			key, err := jwk.GenerateAES(testCase.preset)
			require.NoError(t, err)

			require.Len(t, key.Key(), testCase.preset.KeySize)
			require.True(t, key.JWKCommon.MatchPreset(jwa.JWKCommon{
				Alg:    testCase.preset.Alg,
				KeyOps: testCase.preset.KeyOps,
				KTY:    jwa.KTYOct,
				Use:    jwa.UseEnc,
			}))
			require.NotEmpty(t, key.KID)

			var octPayload serializers.OctPayload

			require.NoError(t, json.Unmarshal(key.Payload, &octPayload))

			decoded, err := serializers.DecodeOct(&octPayload)
			require.NoError(t, err)
			require.Equal(t, key.Key(), decoded)
		})
	}
}

func TestConsumeAES(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name      string
		preset    jwk.AESPreset
		key       *jwk.Key[[]byte]
		expectErr error
	}{
		{
			name:   "A128CBC",
			preset: jwk.A128CBC,
			key:    mustAES(t, jwk.A128CBC),
		},
		{
			name:   "A192CBC",
			preset: jwk.A192CBC,
			key:    mustAES(t, jwk.A192CBC),
		},
		{
			name:   "A256CBC",
			preset: jwk.A256CBC,
			key:    mustAES(t, jwk.A256CBC),
		},
		{
			name:   "A128GCM",
			preset: jwk.A128GCM,
			key:    mustAES(t, jwk.A128GCM),
		},
		{
			name:   "A192GCM",
			preset: jwk.A192GCM,
			key:    mustAES(t, jwk.A192GCM),
		},
		{
			name:   "A256GCM",
			preset: jwk.A256GCM,
			key:    mustAES(t, jwk.A256GCM),
		},

		{
			name:   "A128KW",
			preset: jwk.A128KW,
			key:    mustAES(t, jwk.A128KW),
		},
		{
			name:   "A192KW",
			preset: jwk.A192KW,
			key:    mustAES(t, jwk.A192KW),
		},
		{
			name:   "A256KW",
			preset: jwk.A256KW,
			key:    mustAES(t, jwk.A256KW),
		},
		{
			name:   "A128GCMKW",
			preset: jwk.A128GCMKW,
			key:    mustAES(t, jwk.A128GCMKW),
		},
		{
			name:   "A192GCMKW",
			preset: jwk.A192GCMKW,
			key:    mustAES(t, jwk.A192GCMKW),
		},
		{
			name:   "A256GCMKW",
			preset: jwk.A256GCMKW,
			key:    mustAES(t, jwk.A256GCMKW),
		},

		{
			name:      "InvalidKey",
			preset:    jwk.A128CBC,
			key:       newBullshitKey[[]byte](t, "kid-1"),
			expectErr: jwk.ErrJWKMismatch,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			key, err := jwk.ConsumeAES(testCase.key.JWK, testCase.preset)
			require.ErrorIs(t, err, testCase.expectErr)

			if err == nil {
				require.Equal(t, testCase.key.Key(), key.Key())
			}
		})
	}
}

func TestAESSource(t *testing.T) {
	t.Parallel()

	errFoo := errors.New("foo")

	testCases := []struct {
		name   string
		preset jwk.AESPreset
	}{
		{
			name:   "A128CBC",
			preset: jwk.A128CBC,
		},
		{
			name:   "A192CBC",
			preset: jwk.A192CBC,
		},
		{
			name:   "A256CBC",
			preset: jwk.A256CBC,
		},
		{
			name:   "A128GCM",
			preset: jwk.A128GCM,
		},
		{
			name:   "A192GCM",
			preset: jwk.A192GCM,
		},
		{
			name:   "A256GCM",
			preset: jwk.A256GCM,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			keys := make([]*jwk.Key[[]byte], 3)
			for i := range keys {
				key, err := jwk.GenerateAES(testCase.preset)
				require.NoError(t, err)

				keys[i] = key
			}

			t.Run("OK", func(t *testing.T) {
				t.Parallel()

				fetcher := func(_ context.Context) ([]*jwa.JWK, error) {
					mapped := lo.Map(keys, func(item *jwk.Key[[]byte], _ int) *jwa.JWK {
						return item.JWK
					})

					return mapped, nil
				}

				source := jwk.NewAESSource(jwk.SourceConfig{Fetch: fetcher}, testCase.preset)
				require.NotNil(t, source)

				fetchedKeys, err := source.List(t.Context())
				require.NoError(t, err)
				require.Equal(t, keys, fetchedKeys)
			})

			t.Run("FetchError", func(t *testing.T) {
				t.Parallel()

				fetcher := func(_ context.Context) ([]*jwa.JWK, error) {
					return nil, errFoo
				}

				source := jwk.NewAESSource(jwk.SourceConfig{Fetch: fetcher}, testCase.preset)
				require.NotNil(t, source)

				_, err := source.List(t.Context())
				require.ErrorIs(t, err, errFoo)
			})

			t.Run("UnsupportedKey", func(t *testing.T) {
				t.Parallel()

				fetcher := func(_ context.Context) ([]*jwa.JWK, error) {
					bullshitKey := newBullshitKey[[]byte](t, "kid-1")

					return []*jwa.JWK{bullshitKey.JWK}, nil
				}

				source := jwk.NewAESSource(jwk.SourceConfig{Fetch: fetcher}, testCase.preset)
				require.NotNil(t, source)

				_, err := source.List(t.Context())
				require.ErrorIs(t, err, jwk.ErrJWKMismatch)
			})
		})
	}
}
