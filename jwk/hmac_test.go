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

func mustHMAC(t *testing.T, preset jwk.HMACPreset) *jwk.Key[[]byte] {
	key, err := jwk.GenerateHMAC(preset)
	require.NoError(t, err)
	return key
}

func TestGenerateHMAC(t *testing.T) {
	testCases := []struct {
		name   string
		preset jwk.HMACPreset
	}{
		{
			name:   "HS256",
			preset: jwk.HS256,
		},
		{
			name:   "HS384",
			preset: jwk.HS384,
		},
		{
			name:   "HS512",
			preset: jwk.HS512,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			key := mustHMAC(t, testCase.preset)
			require.NotNil(t, key)

			require.Len(t, key.Key(), testCase.preset.KeySize)
			require.True(t, key.JWKCommon.MatchPreset(jwa.JWKCommon{
				KTY:    jwa.KTYOct,
				Use:    jwa.UseSig,
				KeyOps: []jwa.KeyOp{jwa.KeyOpSign, jwa.KeyOpVerify},
				Alg:    testCase.preset.Alg,
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

func TestConsumeHMAC(t *testing.T) {
	testCases := []struct {
		name      string
		preset    jwk.HMACPreset
		key       *jwk.Key[[]byte]
		expectErr error
	}{
		{
			name:   "HS256",
			preset: jwk.HS256,
			key:    mustHMAC(t, jwk.HS256),
		},
		{
			name:   "HS384",
			preset: jwk.HS384,
			key:    mustHMAC(t, jwk.HS384),
		},
		{
			name:   "HS512",
			preset: jwk.HS512,
			key:    mustHMAC(t, jwk.HS512),
		},

		{
			name:      "InvalidKey",
			preset:    jwk.HS256,
			key:       newBullshitKey[[]byte]("kid-1"),
			expectErr: jwk.ErrJWKMismatch,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			key, err := jwk.ConsumeHMAC(testCase.key.JWK, testCase.preset)
			require.ErrorIs(t, err, testCase.expectErr)

			if err == nil {
				require.Equal(t, testCase.key.Key(), key.Key())
			}
		})
	}
}

func TestHMACSource(t *testing.T) {
	errFoo := errors.New("foo")

	testCases := []struct {
		name   string
		preset jwk.HMACPreset
	}{
		{
			name:   "HS256",
			preset: jwk.HS256,
		},
		{
			name:   "HS384",
			preset: jwk.HS384,
		},
		{
			name:   "HS512",
			preset: jwk.HS512,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			keys := make([]*jwk.Key[[]byte], 3)
			for i := range keys {
				key, err := jwk.GenerateHMAC(testCase.preset)
				require.NoError(t, err)
				keys[i] = key
			}

			t.Run("OK", func(t *testing.T) {
				fetcher := func(_ context.Context) ([]*jwa.JWK, error) {
					mapped := lo.Map(keys, func(item *jwk.Key[[]byte], index int) *jwa.JWK {
						return item.JWK
					})
					return mapped, nil
				}

				source := jwk.NewHMACSource(jwk.SourceConfig{Fetch: fetcher}, testCase.preset)
				require.NotNil(t, source)

				fetchedKeys, err := source.List(context.Background())
				require.NoError(t, err)
				require.Equal(t, keys, fetchedKeys)
			})

			t.Run("FetchError", func(t *testing.T) {
				fetcher := func(_ context.Context) ([]*jwa.JWK, error) {
					return nil, errFoo
				}

				source := jwk.NewHMACSource(jwk.SourceConfig{Fetch: fetcher}, testCase.preset)
				require.NotNil(t, source)

				_, err := source.List(context.Background())
				require.ErrorIs(t, err, errFoo)
			})

			t.Run("UnsupportedKey", func(t *testing.T) {
				fetcher := func(_ context.Context) ([]*jwa.JWK, error) {
					bullshitKey := newBullshitKey[[]byte]("kid-1")
					return []*jwa.JWK{bullshitKey.JWK}, nil
				}

				source := jwk.NewHMACSource(jwk.SourceConfig{Fetch: fetcher}, testCase.preset)
				require.NotNil(t, source)

				_, err := source.List(context.Background())
				require.ErrorIs(t, err, jwk.ErrJWKMismatch)
			})
		})
	}
}
