package jwk_test

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"

	"github.com/samber/lo"
	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt/jwa"
	"github.com/a-novel-kit/jwt/jwk"
	"github.com/a-novel-kit/jwt/jwk/serializers"
)

func mustED25519(t *testing.T) (*jwk.Key[ed25519.PrivateKey], *jwk.Key[ed25519.PublicKey]) {
	t.Helper()

	private, public, err := jwk.GenerateED25519()
	require.NoError(t, err)

	return private, public
}

func TestGenerateED25519(t *testing.T) {
	t.Parallel()

	privateKey, publicKey, err := jwk.GenerateED25519()
	require.NoError(t, err)

	require.True(t, privateKey.MatchPreset(jwa.JWKCommon{
		KTY:    jwa.KTYOKP,
		Use:    jwa.UseSig,
		KeyOps: jwa.KeyOps{jwa.KeyOpSign},
		Alg:    jwa.EdDSA,
	}))
	require.NotEmpty(t, privateKey.KID)

	require.True(t, publicKey.MatchPreset(jwa.JWKCommon{
		KTY:    jwa.KTYOKP,
		Use:    jwa.UseSig,
		KeyOps: jwa.KeyOps{jwa.KeyOpVerify},
		Alg:    jwa.EdDSA,
	}))
	require.Equal(t, privateKey.KID, publicKey.KID)

	t.Run("ParsePrivate", func(t *testing.T) {
		t.Parallel()

		var edPayload serializers.EDPayload

		require.NoError(t, json.Unmarshal(privateKey.Payload, &edPayload))

		decodedPrivate, decodedPublic, err := serializers.DecodeED(&edPayload)
		require.NoError(t, err)

		require.NotNil(t, decodedPrivate)
		require.NotNil(t, decodedPublic)

		require.True(t, privateKey.Key().Equal(decodedPrivate))
		require.True(t, publicKey.Key().Equal(decodedPublic))
	})

	t.Run("ParsePublic", func(t *testing.T) {
		t.Parallel()

		var edPayload serializers.EDPayload

		require.NoError(t, json.Unmarshal(publicKey.Payload, &edPayload))

		decodedPrivate, decodedPublic, err := serializers.DecodeED(&edPayload)
		require.NoError(t, err)

		require.Nil(t, decodedPrivate)
		require.NotNil(t, decodedPublic)

		require.True(t, publicKey.Key().Equal(decodedPublic))
	})
}

func TestConsumeED25519(t *testing.T) {
	t.Parallel()

	private, public := mustED25519(t)

	testCases := []struct {
		name      string
		private   *jwk.Key[ed25519.PrivateKey]
		public    *jwk.Key[ed25519.PublicKey]
		expectErr error
	}{
		{
			name:    "Success",
			private: private,
			public:  public,
		},
		{
			name:      "Mismatch",
			private:   newBullshitKey[ed25519.PrivateKey](t, "kid-1"),
			public:    newBullshitKey[ed25519.PublicKey](t, "kid-2"),
			expectErr: jwk.ErrJWKMismatch,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			t.Run("Private", func(t *testing.T) {
				t.Parallel()

				privateKey, publicKey, err := jwk.ConsumeED25519(testCase.private.JWK)
				require.ErrorIs(t, err, testCase.expectErr)

				if err == nil {
					require.True(t, publicKey.Key().Equal(public.Key()))
					require.True(t, privateKey.Key().Equal(private.Key()))
				}
			})

			t.Run("Public", func(t *testing.T) {
				t.Parallel()

				privateKey, publicKey, err := jwk.ConsumeED25519(testCase.public.JWK)
				require.ErrorIs(t, err, testCase.expectErr)

				if err == nil {
					require.True(t, publicKey.Key().Equal(public.Key()))
					require.Nil(t, privateKey)
				}
			})
		})
	}
}

func TestED25519Source(t *testing.T) {
	t.Parallel()

	errFoo := errors.New("foo")

	privateKeys := make([]*jwk.Key[ed25519.PrivateKey], 3)
	publicKeys := make([]*jwk.Key[ed25519.PublicKey], 3)

	for i := range privateKeys {
		private, public, err := jwk.GenerateED25519()
		require.NoError(t, err)

		privateKeys[i] = private
		publicKeys[i] = public
	}

	t.Run("Private", func(t *testing.T) {
		t.Parallel()

		t.Run("OK", func(t *testing.T) {
			t.Parallel()

			fetcher := func(_ context.Context) ([]*jwa.JWK, error) {
				mapped := lo.Map(privateKeys, func(item *jwk.Key[ed25519.PrivateKey], _ int) *jwa.JWK {
					return item.JWK
				})

				return mapped, nil
			}

			source := jwk.NewED25519PrivateSource(jwk.SourceConfig{Fetch: fetcher})
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

			source := jwk.NewED25519PrivateSource(jwk.SourceConfig{Fetch: fetcher})
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

			source := jwk.NewED25519PrivateSource(jwk.SourceConfig{Fetch: fetcher})
			require.NotNil(t, source)

			_, err := source.List(t.Context())
			require.ErrorIs(t, err, jwk.ErrJWKMismatch)
		})

		t.Run("PublicKeys", func(t *testing.T) {
			t.Parallel()

			fetcher := func(_ context.Context) ([]*jwa.JWK, error) {
				mapped := lo.Map(publicKeys, func(item *jwk.Key[ed25519.PublicKey], _ int) *jwa.JWK {
					return item.JWK
				})

				return mapped, nil
			}

			source := jwk.NewED25519PrivateSource(jwk.SourceConfig{Fetch: fetcher})
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
				mapped := lo.Map(publicKeys, func(item *jwk.Key[ed25519.PublicKey], _ int) *jwa.JWK {
					return item.JWK
				})

				return mapped, nil
			}

			source := jwk.NewED25519PublicSource(jwk.SourceConfig{Fetch: fetcher})
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

			source := jwk.NewED25519PublicSource(jwk.SourceConfig{Fetch: fetcher})
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

			source := jwk.NewED25519PublicSource(jwk.SourceConfig{Fetch: fetcher})
			require.NotNil(t, source)

			_, err := source.List(t.Context())
			require.ErrorIs(t, err, jwk.ErrJWKMismatch)
		})

		t.Run("PrivateKeys", func(t *testing.T) {
			t.Parallel()

			fetcher := func(_ context.Context) ([]*jwa.JWK, error) {
				mapped := lo.Map(privateKeys, func(item *jwk.Key[ed25519.PrivateKey], _ int) *jwa.JWK {
					return item.JWK
				})

				return mapped, nil
			}

			source := jwk.NewED25519PublicSource(jwk.SourceConfig{Fetch: fetcher})
			require.NotNil(t, source)

			_, err := source.List(t.Context())
			require.ErrorIs(t, err, jwk.ErrJWKMismatch)
		})
	})
}
