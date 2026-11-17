package jws_test

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt/v2"
	"github.com/a-novel-kit/jwt/v2/jwa"
	"github.com/a-novel-kit/jwt/v2/jwk"
	"github.com/a-novel-kit/jwt/v2/jws"
)

// testClaims is the claims set every test token carries.
var testClaims = map[string]any{"foo": "bar"}

// A signatureCase is one JWS algorithm under test. newKeys generates a fresh key pair with the
// single-key plugins built on it, and newSourced builds the sourced plugins drawing keys from source.
type signatureCase struct {
	alg        jwa.Alg
	newKeys    func() signatureKeys
	newSourced func(source *jwk.Source) (jwt.ProducerPlugin, jwt.RecipientPlugin)
}

// signatureKeys is a generated key pair as JSON Web Keys, with the single-key plugins built on it.
// An HMAC secret signs and verifies, so both of its JWKs are the same key.
type signatureKeys struct {
	signing      *jwa.JWK
	verification *jwa.JWK
	signer       jwt.ProducerPlugin
	verifier     jwt.RecipientPlugin
}

// signatureCases lists every algorithm the package signs with.
var signatureCases = []signatureCase{
	hmacCase(jwk.HS256, jws.HS256),
	hmacCase(jwk.HS384, jws.HS384),
	hmacCase(jwk.HS512, jws.HS512),
	rsaCase(jwk.RS256, jws.RS256),
	rsaCase(jwk.RS384, jws.RS384),
	rsaCase(jwk.RS512, jws.RS512),
	rsaCase(jwk.PS256, jws.PS256),
	rsaCase(jwk.PS384, jws.PS384),
	rsaCase(jwk.PS512, jws.PS512),
	ecdsaCase(jwk.ES256, jws.ES256),
	ecdsaCase(jwk.ES384, jws.ES384),
	ecdsaCase(jwk.ES512, jws.ES512),
	ed25519Case(),
	mldsaCase(jwk.MLDSA44),
	mldsaCase(jwk.MLDSA65),
	mldsaCase(jwk.MLDSA87),
}

func hmacCase(keyPreset jwk.HMACPreset, preset jws.HMACPreset) signatureCase {
	return signatureCase{
		alg: preset.Alg,
		newKeys: func() signatureKeys {
			key, err := jwk.GenerateHMAC(keyPreset)
			if err != nil {
				panic(err)
			}

			return signatureKeys{
				signing:      key.JWK,
				verification: key.JWK,
				signer:       jws.NewHMACSigner(key.Key(), preset),
				verifier:     jws.NewHMACVerifier(key.Key(), preset),
			}
		},
		newSourced: func(source *jwk.Source) (jwt.ProducerPlugin, jwt.RecipientPlugin) {
			return jws.NewSourcedHMACSigner(source, preset), jws.NewSourcedHMACVerifier(source, preset)
		},
	}
}

func rsaCase(keyPreset jwk.RSAPreset, preset jws.RSAPreset) signatureCase {
	return signatureCase{
		alg: preset.Alg,
		newKeys: func() signatureKeys {
			privateKey, publicKey, err := jwk.GenerateRSA(keyPreset)
			if err != nil {
				panic(err)
			}

			return signatureKeys{
				signing:      privateKey.JWK,
				verification: publicKey.JWK,
				signer:       jws.NewRSASigner(privateKey.Key(), preset),
				verifier:     jws.NewRSAVerifier(publicKey.Key(), preset),
			}
		},
		newSourced: func(source *jwk.Source) (jwt.ProducerPlugin, jwt.RecipientPlugin) {
			return jws.NewSourcedRSASigner(source, preset), jws.NewSourcedRSAVerifier(source, preset)
		},
	}
}

func ecdsaCase(keyPreset jwk.ECDSAPreset, preset jws.ECDSAPreset) signatureCase {
	return signatureCase{
		alg: preset.Alg,
		newKeys: func() signatureKeys {
			privateKey, publicKey, err := jwk.GenerateECDSA(keyPreset)
			if err != nil {
				panic(err)
			}

			return signatureKeys{
				signing:      privateKey.JWK,
				verification: publicKey.JWK,
				signer:       jws.NewECDSASigner(privateKey.Key(), preset),
				verifier:     jws.NewECDSAVerifier(publicKey.Key(), preset),
			}
		},
		newSourced: func(source *jwk.Source) (jwt.ProducerPlugin, jwt.RecipientPlugin) {
			return jws.NewSourcedECDSASigner(source, preset), jws.NewSourcedECDSAVerifier(source, preset)
		},
	}
}

func ed25519Case() signatureCase {
	return signatureCase{
		alg: jwa.Ed25519,
		newKeys: func() signatureKeys {
			privateKey, publicKey, err := jwk.GenerateED25519()
			if err != nil {
				panic(err)
			}

			return signatureKeys{
				signing:      privateKey.JWK,
				verification: publicKey.JWK,
				signer:       jws.NewED25519Signer(privateKey.Key()),
				verifier:     jws.NewED25519Verifier(publicKey.Key()),
			}
		},
		newSourced: func(source *jwk.Source) (jwt.ProducerPlugin, jwt.RecipientPlugin) {
			return jws.NewSourcedED25519Signer(source), jws.NewSourcedED25519Verifier(source)
		},
	}
}

func mldsaCase(keyPreset jwk.MLDSAPreset) signatureCase {
	return signatureCase{
		alg: keyPreset.Alg,
		newKeys: func() signatureKeys {
			privateKey, publicKey, err := jwk.GenerateMLDSA(keyPreset)
			if err != nil {
				panic(err)
			}

			return signatureKeys{
				signing:      privateKey.JWK,
				verification: publicKey.JWK,
				signer:       jws.NewMLDSASigner(privateKey.Key()),
				verifier:     jws.NewMLDSAVerifier(publicKey.Key()),
			}
		},
		newSourced: func(source *jwk.Source) (jwt.ProducerPlugin, jwt.RecipientPlugin) {
			return jws.NewSourcedMLDSASigner(source), jws.NewSourcedMLDSAVerifier(source)
		},
	}
}

// newSource returns a [jwk.Source] serving keys in the order given.
func newSource(keys ...*jwa.JWK) *jwk.Source {
	return jwk.NewSource(jwk.SourceConfig{
		Fetch: func(_ context.Context) ([]*jwa.JWK, error) { return keys, nil },
	})
}

// withKeyOps returns a copy of key that lists only ops, leaving the key material untouched.
func withKeyOps(key *jwa.JWK, ops ...jwa.KeyOp) *jwa.JWK {
	relabeled := *key
	relabeled.KeyOps = ops

	return &relabeled
}

// issue signs testClaims with signer. A non-empty kid names the signing key in the header, as an
// issuer does to pick one key of its source.
func issue(t *testing.T, signer jwt.ProducerPlugin, kid string) string {
	t.Helper()

	config := jwt.ProducerConfig{Plugins: []jwt.ProducerPlugin{signer}}
	if kid != "" {
		config.StaticPlugins = []jwt.ProducerStaticPlugin{keyIDPlugin(kid)}
	}

	token, err := jwt.NewProducer(config).Issue(t.Context(), testClaims, nil)
	require.NoError(t, err)

	return token
}

// keyIDPlugin stamps its key ID into the header.
type keyIDPlugin string

func (kid keyIDPlugin) Header(_ context.Context, header *jwa.JWH) (*jwa.JWH, error) {
	header.KID = string(kid)

	return header, nil
}

// consume verifies token with verifier and checks it carries testClaims.
func consume(t *testing.T, verifier jwt.RecipientPlugin, token string) error {
	t.Helper()

	var claims map[string]any

	err := jwt.NewRecipient(jwt.RecipientConfig{Plugins: []jwt.RecipientPlugin{verifier}}).
		Consume(t.Context(), token, &claims)
	if err == nil {
		require.Equal(t, testClaims, claims)
	}

	return err
}

// readVector decodes a JSON test vector file of testdata into dst.
func readVector(t *testing.T, name string, dst any) {
	t.Helper()

	raw, err := os.ReadFile("testdata/" + name)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, dst))
}
