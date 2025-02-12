package jwk_test

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"testing"

	"github.com/samber/lo"
	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt/jwa"
	"github.com/a-novel-kit/jwt/jwk"
	"github.com/a-novel-kit/jwt/jwk/serializers"
)

func mustECDSA(t *testing.T, preset jwk.ECDSAPreset) (*jwk.Key[*ecdsa.PrivateKey], *jwk.Key[*ecdsa.PublicKey]) {
	t.Helper()

	private, public, err := jwk.GenerateECDSA(preset)
	require.NoError(t, err)

	return private, public
}

func TestGenerateECDSA(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name   string
		preset jwk.ECDSAPreset
	}{
		{
			name:   "ES256",
			preset: jwk.ES256,
		},
		{
			name:   "ES384",
			preset: jwk.ES384,
		},
		{
			name:   "ES512",
			preset: jwk.ES512,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			privateKey, publicKey, err := jwk.GenerateECDSA(testCase.preset)
			require.NoError(t, err)

			require.True(t, privateKey.JWKCommon.MatchPreset(jwa.JWKCommon{
				KTY:    jwa.KTYEC,
				Use:    jwa.UseSig,
				KeyOps: []jwa.KeyOp{jwa.KeyOpSign},
				Alg:    testCase.preset.Alg,
			}))
			require.NotEmpty(t, privateKey.KID)

			require.True(t, publicKey.JWKCommon.MatchPreset(jwa.JWKCommon{
				KTY:    jwa.KTYEC,
				Use:    jwa.UseSig,
				KeyOps: []jwa.KeyOp{jwa.KeyOpVerify},
				Alg:    testCase.preset.Alg,
			}))
			require.Equal(t, privateKey.KID, publicKey.KID)

			t.Run("ParsePrivate", func(t *testing.T) {
				t.Parallel()

				var ecPayload serializers.ECPayload

				require.NoError(t, json.Unmarshal(privateKey.Payload, &ecPayload))

				decodedPrivate, decodedPublic, err := serializers.DecodeEC(&ecPayload)
				require.NoError(t, err)

				require.NotNil(t, decodedPrivate)
				require.NotNil(t, decodedPublic)

				require.True(t, privateKey.Key().Equal(decodedPrivate))
				require.True(t, publicKey.Key().Equal(decodedPublic))
			})

			t.Run("ParsePublic", func(t *testing.T) {
				t.Parallel()

				var ecPayload serializers.ECPayload

				require.NoError(t, json.Unmarshal(publicKey.Payload, &ecPayload))

				decodedPrivate, decodedPublic, err := serializers.DecodeEC(&ecPayload)
				require.NoError(t, err)

				require.Nil(t, decodedPrivate)
				require.NotNil(t, decodedPublic)

				require.True(t, publicKey.Key().Equal(decodedPublic))
			})
		})
	}
}

func TestConsumeECDSA(t *testing.T) {
	t.Parallel()

	es256Private, es256Public := mustECDSA(t, jwk.ES256)
	es384Private, es384Public := mustECDSA(t, jwk.ES384)
	es512Private, es512Public := mustECDSA(t, jwk.ES512)

	testCases := []struct {
		name      string
		preset    jwk.ECDSAPreset
		private   *jwk.Key[*ecdsa.PrivateKey]
		public    *jwk.Key[*ecdsa.PublicKey]
		expectErr error
	}{
		{
			name:    "ES256",
			preset:  jwk.ES256,
			private: es256Private,
			public:  es256Public,
		},
		{
			name:    "ES384",
			preset:  jwk.ES384,
			private: es384Private,
			public:  es384Public,
		},
		{
			name:    "ES512",
			preset:  jwk.ES512,
			private: es512Private,
			public:  es512Public,
		},

		{
			name:      "Mismatch",
			preset:    jwk.ES256,
			private:   newBullshitKey[*ecdsa.PrivateKey](t, "kid-1"),
			public:    newBullshitKey[*ecdsa.PublicKey](t, "kid-2"),
			expectErr: jwk.ErrJWKMismatch,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			t.Run("Private", func(t *testing.T) {
				t.Parallel()

				privateKey, publicKey, err := jwk.ConsumeECDSA(testCase.private.JWK, testCase.preset)
				require.ErrorIs(t, err, testCase.expectErr)

				if err == nil {
					require.True(t, publicKey.Key().Equal(testCase.public.Key()))
					require.True(t, privateKey.Key().Equal(testCase.private.Key()))
				}
			})

			t.Run("Public", func(t *testing.T) {
				t.Parallel()

				privateKey, publicKey, err := jwk.ConsumeECDSA(testCase.public.JWK, testCase.preset)
				require.ErrorIs(t, err, testCase.expectErr)

				if err == nil {
					require.True(t, publicKey.Key().Equal(testCase.public.Key()))
					require.Nil(t, privateKey)
				}
			})
		})
	}
}

func TestECDSASource(t *testing.T) {
	t.Parallel()

	errFoo := errors.New("foo")

	testCases := []struct {
		name   string
		preset jwk.ECDSAPreset
	}{
		{
			name:   "ES256",
			preset: jwk.ES256,
		},
		{
			name:   "ES384",
			preset: jwk.ES384,
		},
		{
			name:   "ES512",
			preset: jwk.ES512,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			privateKeys := make([]*jwk.Key[*ecdsa.PrivateKey], 3)
			publicKeys := make([]*jwk.Key[*ecdsa.PublicKey], 3)

			for i := range privateKeys {
				private, public, err := jwk.GenerateECDSA(testCase.preset)
				require.NoError(t, err)

				privateKeys[i] = private
				publicKeys[i] = public
			}

			t.Run("Private", func(t *testing.T) {
				t.Parallel()

				t.Run("OK", func(t *testing.T) {
					t.Parallel()

					fetcher := func(_ context.Context) ([]*jwa.JWK, error) {
						mapped := lo.Map(privateKeys, func(item *jwk.Key[*ecdsa.PrivateKey], _ int) *jwa.JWK {
							return item.JWK
						})

						return mapped, nil
					}

					source := jwk.NewECDSAPrivateSource(jwk.SourceConfig{Fetch: fetcher}, testCase.preset)
					require.NotNil(t, source)

					fetchedKeys, err := source.List(t.Context())
					require.NoError(t, err)
					require.Len(t, fetchedKeys, len(privateKeys))

					for i, key := range fetchedKeys {
						require.True(t, key.Key().Equal(privateKeys[i].Key()))
						require.Equal(t, key.JWK, privateKeys[i].JWK)
					}
				})

				t.Run("FetchError", func(t *testing.T) {
					t.Parallel()

					fetcher := func(_ context.Context) ([]*jwa.JWK, error) {
						return nil, errFoo
					}

					source := jwk.NewECDSAPrivateSource(jwk.SourceConfig{Fetch: fetcher}, testCase.preset)
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

					source := jwk.NewECDSAPrivateSource(jwk.SourceConfig{Fetch: fetcher}, testCase.preset)
					require.NotNil(t, source)

					_, err := source.List(t.Context())
					require.ErrorIs(t, err, jwk.ErrJWKMismatch)
				})

				t.Run("PublicKeys", func(t *testing.T) {
					t.Parallel()

					fetcher := func(_ context.Context) ([]*jwa.JWK, error) {
						mapped := lo.Map(publicKeys, func(item *jwk.Key[*ecdsa.PublicKey], _ int) *jwa.JWK {
							return item.JWK
						})

						return mapped, nil
					}

					source := jwk.NewECDSAPrivateSource(jwk.SourceConfig{Fetch: fetcher}, testCase.preset)
					require.NotNil(t, source)

					_, err := source.List(t.Context())
					require.ErrorIs(t, err, jwk.ErrJWKMismatch)
				})
			})

			t.Run("Public", func(t *testing.T) {
				t.Parallel()

				t.Run("OK", func(t *testing.T) {
					t.Parallel()

					fetcher := func(_ context.Context) ([]*jwa.JWK, error) {
						mapped := lo.Map(publicKeys, func(item *jwk.Key[*ecdsa.PublicKey], _ int) *jwa.JWK {
							return item.JWK
						})

						return mapped, nil
					}

					source := jwk.NewECDSAPublicSource(jwk.SourceConfig{Fetch: fetcher}, testCase.preset)
					require.NotNil(t, source)

					fetchedKeys, err := source.List(t.Context())
					require.NoError(t, err)
					require.Len(t, fetchedKeys, len(publicKeys))

					for i, key := range fetchedKeys {
						require.True(t, key.Key().Equal(publicKeys[i].Key()))
						require.Equal(t, key.JWK, publicKeys[i].JWK)
					}
				})

				t.Run("FetchError", func(t *testing.T) {
					t.Parallel()

					fetcher := func(_ context.Context) ([]*jwa.JWK, error) {
						return nil, errFoo
					}

					source := jwk.NewECDSAPublicSource(jwk.SourceConfig{Fetch: fetcher}, testCase.preset)
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

					source := jwk.NewECDSAPublicSource(jwk.SourceConfig{Fetch: fetcher}, testCase.preset)
					require.NotNil(t, source)

					_, err := source.List(t.Context())
					require.ErrorIs(t, err, jwk.ErrJWKMismatch)
				})

				t.Run("PrivateKeys", func(t *testing.T) {
					t.Parallel()

					fetcher := func(_ context.Context) ([]*jwa.JWK, error) {
						mapped := lo.Map(privateKeys, func(item *jwk.Key[*ecdsa.PrivateKey], _ int) *jwa.JWK {
							return item.JWK
						})

						return mapped, nil
					}

					source := jwk.NewECDSAPublicSource(jwk.SourceConfig{Fetch: fetcher}, testCase.preset)
					require.NotNil(t, source)

					_, err := source.List(t.Context())
					require.ErrorIs(t, err, jwk.ErrJWKMismatch)
				})
			})
		})
	}
}
