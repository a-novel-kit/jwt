package jwk_test

import (
	"context"
	"crypto/ecdh"
	"encoding/json"
	"errors"
	"testing"

	"github.com/samber/lo"
	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt/jwa"
	"github.com/a-novel-kit/jwt/jwk"
	"github.com/a-novel-kit/jwt/jwk/serializers"
)

func mustECDH(t *testing.T) (*jwk.Key[*ecdh.PrivateKey], *jwk.Key[*ecdh.PublicKey]) {
	t.Helper()

	private, public, err := jwk.GenerateECDH()
	require.NoError(t, err)

	return private, public
}

func TestGenerateECDH(t *testing.T) {
	t.Parallel()

	privateKey, publicKey, err := jwk.GenerateECDH()
	require.NoError(t, err)

	require.True(t, privateKey.JWKCommon.MatchPreset(jwa.JWKCommon{
		KTY:    jwa.KTYOKP,
		Use:    jwa.UseEnc,
		KeyOps: []jwa.KeyOp{jwa.KeyOpDeriveKey},
		Alg:    jwa.ECDHES,
	}))
	require.NotEmpty(t, privateKey.KID)

	require.True(t, publicKey.JWKCommon.MatchPreset(jwa.JWKCommon{
		KTY:    jwa.KTYOKP,
		Use:    jwa.UseEnc,
		KeyOps: []jwa.KeyOp{jwa.KeyOpDeriveKey},
		Alg:    jwa.ECDHES,
	}))
	require.Equal(t, privateKey.KID, publicKey.KID)

	t.Run("ParsePrivate", func(t *testing.T) {
		t.Parallel()

		var ecdhPayload serializers.ECDHPayload

		require.NoError(t, json.Unmarshal(privateKey.Payload, &ecdhPayload))

		decodedPrivate, decodedPublic, err := serializers.DecodeECDH(&ecdhPayload)
		require.NoError(t, err)

		require.NotNil(t, decodedPrivate)
		require.NotNil(t, decodedPublic)

		require.True(t, privateKey.Key().Equal(decodedPrivate))
		require.True(t, publicKey.Key().Equal(decodedPublic))
	})

	t.Run("ParsePublic", func(t *testing.T) {
		t.Parallel()

		var ecdhPayload serializers.ECDHPayload

		require.NoError(t, json.Unmarshal(publicKey.Payload, &ecdhPayload))

		decodedPrivate, decodedPublic, err := serializers.DecodeECDH(&ecdhPayload)
		require.NoError(t, err)

		require.Nil(t, decodedPrivate)
		require.NotNil(t, decodedPublic)

		require.True(t, publicKey.Key().Equal(decodedPublic))
	})
}

func TestConsumeECDH(t *testing.T) {
	t.Parallel()

	private, public := mustECDH(t)

	testCases := []struct {
		name      string
		private   *jwk.Key[*ecdh.PrivateKey]
		public    *jwk.Key[*ecdh.PublicKey]
		expectErr error
	}{
		{
			name:    "Success",
			private: private,
			public:  public,
		},
		{
			name:      "Mismatch",
			private:   newBullshitKey[*ecdh.PrivateKey](t, "kid-1"),
			public:    newBullshitKey[*ecdh.PublicKey](t, "kid-2"),
			expectErr: jwk.ErrJWKMismatch,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			t.Run("Private", func(t *testing.T) {
				t.Parallel()

				privateKey, publicKey, err := jwk.ConsumeECDH(testCase.private.JWK)
				require.ErrorIs(t, err, testCase.expectErr)

				if err == nil {
					require.True(t, publicKey.Key().Equal(public.Key()))
					require.True(t, privateKey.Key().Equal(private.Key()))
				}
			})

			t.Run("Public", func(t *testing.T) {
				t.Parallel()

				privateKey, publicKey, err := jwk.ConsumeECDH(testCase.public.JWK)
				require.ErrorIs(t, err, testCase.expectErr)

				if err == nil {
					require.True(t, publicKey.Key().Equal(public.Key()))
					require.Nil(t, privateKey)
				}
			})
		})
	}
}

func TestECDHSource(t *testing.T) {
	t.Parallel()

	errFoo := errors.New("foo")

	privateKeys := make([]*jwk.Key[*ecdh.PrivateKey], 3)
	publicKeys := make([]*jwk.Key[*ecdh.PublicKey], 3)

	for i := range privateKeys {
		private, public, err := jwk.GenerateECDH()
		require.NoError(t, err)

		privateKeys[i] = private
		publicKeys[i] = public
	}

	t.Run("Private", func(t *testing.T) {
		t.Parallel()

		t.Run("OK", func(t *testing.T) {
			t.Parallel()

			fetcher := func(_ context.Context) ([]*jwa.JWK, error) {
				mapped := lo.Map(privateKeys, func(item *jwk.Key[*ecdh.PrivateKey], _ int) *jwa.JWK {
					return item.JWK
				})

				return mapped, nil
			}

			source := jwk.NewECDHPrivateSource(jwk.SourceConfig{Fetch: fetcher})
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

			source := jwk.NewECDHPrivateSource(jwk.SourceConfig{Fetch: fetcher})
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

			source := jwk.NewECDHPrivateSource(jwk.SourceConfig{Fetch: fetcher})
			require.NotNil(t, source)

			_, err := source.List(context.Background())
			require.ErrorIs(t, err, jwk.ErrJWKMismatch)
		})

		t.Run("PublicKeys", func(t *testing.T) {
			t.Parallel()

			fetcher := func(_ context.Context) ([]*jwa.JWK, error) {
				mapped := lo.Map(publicKeys, func(item *jwk.Key[*ecdh.PublicKey], _ int) *jwa.JWK {
					return item.JWK
				})

				return mapped, nil
			}

			source := jwk.NewECDHPrivateSource(jwk.SourceConfig{Fetch: fetcher})
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
				mapped := lo.Map(publicKeys, func(item *jwk.Key[*ecdh.PublicKey], _ int) *jwa.JWK {
					return item.JWK
				})

				return mapped, nil
			}

			source := jwk.NewECDHPublicSource(jwk.SourceConfig{Fetch: fetcher})
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

			source := jwk.NewECDHPublicSource(jwk.SourceConfig{Fetch: fetcher})
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

			source := jwk.NewECDHPublicSource(jwk.SourceConfig{Fetch: fetcher})
			require.NotNil(t, source)

			_, err := source.List(context.Background())
			require.ErrorIs(t, err, jwk.ErrJWKMismatch)
		})

		t.Run("PrivateKeys", func(t *testing.T) {
			t.Parallel()

			fetcher := func(_ context.Context) ([]*jwa.JWK, error) {
				mapped := lo.Map(privateKeys, func(item *jwk.Key[*ecdh.PrivateKey], _ int) *jwa.JWK {
					return item.JWK
				})

				return mapped, nil
			}

			source := jwk.NewECDHPublicSource(jwk.SourceConfig{Fetch: fetcher})
			require.NotNil(t, source)

			_, err := source.List(context.Background())
			require.ErrorIs(t, err, jwk.ErrJWKMismatch)
		})
	})
}
