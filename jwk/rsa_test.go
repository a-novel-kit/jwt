package jwk_test

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"testing"

	"github.com/samber/lo"
	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt/jwa"
	"github.com/a-novel-kit/jwt/jwk"
	"github.com/a-novel-kit/jwt/jwk/serializers"
)

func mustRSA(t *testing.T, preset jwk.RSAPreset) (*jwk.Key[*rsa.PrivateKey], *jwk.Key[*rsa.PublicKey]) {
	t.Helper()

	private, public, err := jwk.GenerateRSA(preset)
	require.NoError(t, err)

	return private, public
}

func TestGenerateRSA(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name   string
		preset jwk.RSAPreset
	}{
		{
			name:   "RS256",
			preset: jwk.RS256,
		},
		{
			name:   "RS384",
			preset: jwk.RS384,
		},
		{
			name:   "RS512",
			preset: jwk.RS512,
		},

		{
			name:   "PS256",
			preset: jwk.PS256,
		},
		{
			name:   "PS384",
			preset: jwk.PS384,
		},
		{
			name:   "PS512",
			preset: jwk.PS512,
		},

		{
			name:   "RSAOAEP",
			preset: jwk.RSAOAEP,
		},
		{
			name:   "RSAOAEP256",
			preset: jwk.RSAOAEP256,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			privateKey, publicKey, err := jwk.GenerateRSA(testCase.preset)
			require.NoError(t, err)

			require.True(t, privateKey.JWKCommon.MatchPreset(jwa.JWKCommon{
				KTY:    jwa.KTYRSA,
				Use:    testCase.preset.Use,
				KeyOps: testCase.preset.PrivateKeyOps,
				Alg:    testCase.preset.Alg,
			}))
			require.NotEmpty(t, privateKey.KID)

			require.True(t, publicKey.JWKCommon.MatchPreset(jwa.JWKCommon{
				KTY:    jwa.KTYRSA,
				Use:    testCase.preset.Use,
				KeyOps: testCase.preset.PublicKeyOps,
				Alg:    testCase.preset.Alg,
			}))
			require.Equal(t, privateKey.KID, publicKey.KID)

			t.Run("ParsePrivate", func(t *testing.T) {
				t.Parallel()

				var rsaPayload serializers.RSAPayload

				require.NoError(t, json.Unmarshal(privateKey.Payload, &rsaPayload))

				decodedPrivate, decodedPublic, err := serializers.DecodeRSA(&rsaPayload)
				require.NoError(t, err)

				require.NotNil(t, decodedPrivate)
				require.NotNil(t, decodedPublic)

				require.True(t, privateKey.Key().Equal(decodedPrivate))
				require.True(t, publicKey.Key().Equal(decodedPublic))
			})

			t.Run("ParsePublic", func(t *testing.T) {
				t.Parallel()

				var rsaPayload serializers.RSAPayload

				require.NoError(t, json.Unmarshal(publicKey.Payload, &rsaPayload))

				decodedPrivate, decodedPublic, err := serializers.DecodeRSA(&rsaPayload)
				require.NoError(t, err)

				require.Nil(t, decodedPrivate)
				require.NotNil(t, decodedPublic)

				require.True(t, publicKey.Key().Equal(decodedPublic))
			})
		})
	}
}

func TestConsumeRSA(t *testing.T) {
	t.Parallel()

	rs256Private, rs256Public := mustRSA(t, jwk.RS256)
	rs384Private, rs384Public := mustRSA(t, jwk.RS384)
	rs512Private, rs512Public := mustRSA(t, jwk.RS512)
	ps256Private, ps256Public := mustRSA(t, jwk.PS256)
	ps384Private, ps384Public := mustRSA(t, jwk.PS384)
	ps512Private, ps512Public := mustRSA(t, jwk.PS512)

	rsaOAEPPrivate, rsaOAEPPublic := mustRSA(t, jwk.RSAOAEP)
	rsaOAEP256Private, rsaOAEP256Public := mustRSA(t, jwk.RSAOAEP256)

	testCases := []struct {
		name      string
		preset    jwk.RSAPreset
		private   *jwk.Key[*rsa.PrivateKey]
		public    *jwk.Key[*rsa.PublicKey]
		expectErr error
	}{
		{
			name:    "RS256",
			preset:  jwk.RS256,
			private: rs256Private,
			public:  rs256Public,
		},
		{
			name:    "RS384",
			preset:  jwk.RS384,
			private: rs384Private,
			public:  rs384Public,
		},
		{
			name:    "RS512",
			preset:  jwk.RS512,
			private: rs512Private,
			public:  rs512Public,
		},
		{
			name:    "PS256",
			preset:  jwk.PS256,
			private: ps256Private,
			public:  ps256Public,
		},
		{
			name:    "PS384",
			preset:  jwk.PS384,
			private: ps384Private,
			public:  ps384Public,
		},
		{
			name:    "PS512",
			preset:  jwk.PS512,
			private: ps512Private,
			public:  ps512Public,
		},
		{
			name:    "RSAOAEP",
			preset:  jwk.RSAOAEP,
			private: rsaOAEPPrivate,
			public:  rsaOAEPPublic,
		},
		{
			name:    "RSAOAEP256",
			preset:  jwk.RSAOAEP256,
			private: rsaOAEP256Private,
			public:  rsaOAEP256Public,
		},

		{
			name:      "Mismatch",
			preset:    jwk.RS256,
			private:   newBullshitKey[*rsa.PrivateKey](t, "kid-1"),
			public:    newBullshitKey[*rsa.PublicKey](t, "kid-2"),
			expectErr: jwk.ErrJWKMismatch,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			t.Run("Private", func(t *testing.T) {
				t.Parallel()

				privateKey, publicKey, err := jwk.ConsumeRSA(testCase.private.JWK, testCase.preset)
				require.ErrorIs(t, err, testCase.expectErr)

				if err == nil {
					require.True(t, publicKey.Key().Equal(testCase.public.Key()))
					require.True(t, privateKey.Key().Equal(testCase.private.Key()))
				}
			})

			t.Run("Public", func(t *testing.T) {
				t.Parallel()

				privateKey, publicKey, err := jwk.ConsumeRSA(testCase.public.JWK, testCase.preset)
				require.ErrorIs(t, err, testCase.expectErr)

				if err == nil {
					require.True(t, publicKey.Key().Equal(testCase.public.Key()))
					require.Nil(t, privateKey)
				}
			})
		})
	}
}

func TestRSASource(t *testing.T) {
	t.Parallel()

	errFoo := errors.New("foo")

	testCases := []struct {
		name   string
		preset jwk.RSAPreset
	}{
		{
			name:   "RS256",
			preset: jwk.RS256,
		},
		{
			name:   "RS384",
			preset: jwk.RS384,
		},
		{
			name:   "RS512",
			preset: jwk.RS512,
		},
		{
			name:   "PS256",
			preset: jwk.PS256,
		},
		{
			name:   "PS384",
			preset: jwk.PS384,
		},
		{
			name:   "PS512",
			preset: jwk.PS512,
		},
		{
			name:   "RSAOAEP",
			preset: jwk.RSAOAEP,
		},
		{
			name:   "RSAOAEP256",
			preset: jwk.RSAOAEP256,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			privateKeys := make([]*jwk.Key[*rsa.PrivateKey], 3)
			publicKeys := make([]*jwk.Key[*rsa.PublicKey], 3)

			for i := range privateKeys {
				private, public, err := jwk.GenerateRSA(testCase.preset)
				require.NoError(t, err)

				privateKeys[i] = private
				publicKeys[i] = public
			}

			t.Run("Private", func(t *testing.T) {
				t.Parallel()

				t.Run("OK", func(t *testing.T) {
					t.Parallel()

					fetcher := func(_ context.Context) ([]*jwa.JWK, error) {
						mapped := lo.Map(privateKeys, func(item *jwk.Key[*rsa.PrivateKey], _ int) *jwa.JWK {
							return item.JWK
						})

						return mapped, nil
					}

					source := jwk.NewRSAPrivateSource(jwk.SourceConfig{Fetch: fetcher}, testCase.preset)
					require.NotNil(t, source)

					fetchedKeys, err := source.List(context.Background())
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

					source := jwk.NewRSAPrivateSource(jwk.SourceConfig{Fetch: fetcher}, testCase.preset)
					require.NotNil(t, source)

					_, err := source.List(context.Background())
					require.ErrorIs(t, err, errFoo)
				})

				t.Run("UnsupportedKey", func(t *testing.T) {
					t.Parallel()

					fetcher := func(_ context.Context) ([]*jwa.JWK, error) {
						bullshitKey := newBullshitKey[[]byte](t, "kid-1")

						return []*jwa.JWK{bullshitKey.JWK}, nil
					}

					source := jwk.NewRSAPrivateSource(jwk.SourceConfig{Fetch: fetcher}, testCase.preset)
					require.NotNil(t, source)

					_, err := source.List(context.Background())
					require.ErrorIs(t, err, jwk.ErrJWKMismatch)
				})

				t.Run("PublicKeys", func(t *testing.T) {
					t.Parallel()

					fetcher := func(_ context.Context) ([]*jwa.JWK, error) {
						mapped := lo.Map(publicKeys, func(item *jwk.Key[*rsa.PublicKey], _ int) *jwa.JWK {
							return item.JWK
						})

						return mapped, nil
					}

					source := jwk.NewRSAPrivateSource(jwk.SourceConfig{Fetch: fetcher}, testCase.preset)
					require.NotNil(t, source)

					_, err := source.List(context.Background())
					require.ErrorIs(t, err, jwk.ErrJWKMismatch)
				})
			})

			t.Run("Public", func(t *testing.T) {
				t.Parallel()

				t.Run("OK", func(t *testing.T) {
					t.Parallel()

					fetcher := func(_ context.Context) ([]*jwa.JWK, error) {
						mapped := lo.Map(publicKeys, func(item *jwk.Key[*rsa.PublicKey], _ int) *jwa.JWK {
							return item.JWK
						})

						return mapped, nil
					}

					source := jwk.NewRSAPublicSource(jwk.SourceConfig{Fetch: fetcher}, testCase.preset)
					require.NotNil(t, source)

					fetchedKeys, err := source.List(context.Background())
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

					source := jwk.NewRSAPublicSource(jwk.SourceConfig{Fetch: fetcher}, testCase.preset)
					require.NotNil(t, source)

					_, err := source.List(context.Background())
					require.ErrorIs(t, err, errFoo)
				})

				t.Run("UnsupportedKey", func(t *testing.T) {
					t.Parallel()

					fetcher := func(_ context.Context) ([]*jwa.JWK, error) {
						bullshitKey := newBullshitKey[[]byte](t, "kid-1")

						return []*jwa.JWK{bullshitKey.JWK}, nil
					}

					source := jwk.NewRSAPublicSource(jwk.SourceConfig{Fetch: fetcher}, testCase.preset)
					require.NotNil(t, source)

					_, err := source.List(context.Background())
					require.ErrorIs(t, err, jwk.ErrJWKMismatch)
				})

				t.Run("PrivateKeys", func(t *testing.T) {
					t.Parallel()

					fetcher := func(_ context.Context) ([]*jwa.JWK, error) {
						mapped := lo.Map(privateKeys, func(item *jwk.Key[*rsa.PrivateKey], _ int) *jwa.JWK {
							return item.JWK
						})

						return mapped, nil
					}

					source := jwk.NewRSAPublicSource(jwk.SourceConfig{Fetch: fetcher}, testCase.preset)
					require.NotNil(t, source)

					_, err := source.List(context.Background())
					require.ErrorIs(t, err, jwk.ErrJWKMismatch)
				})
			})
		})
	}
}
