package jws_test

import (
	"context"
	"fmt"

	"github.com/a-novel-kit/jwt/v2"
	"github.com/a-novel-kit/jwt/v2/jwa"
	"github.com/a-novel-kit/jwt/v2/jwk"
	"github.com/a-novel-kit/jwt/v2/jws"
)

// ExampleNewSourcedRSAVerifier verifies tokens against the public keys a key server publishes. The
// issuer signs with a sourced signer, which names its key in the token header, so the recipient
// tries that key alone and follows a rotation once its source refreshes.
func ExampleNewSourcedRSAVerifier() {
	ctx := context.Background()

	privateKey, publicKey, err := jwk.GenerateRSA(jwk.RS256)
	if err != nil {
		panic(err)
	}

	// The issuer holds the private keys. A recipient's Fetch would typically read a JWKS endpoint
	// serving the public halves.
	issuerKeys := jwk.NewSource(jwk.SourceConfig{
		Fetch: func(_ context.Context) ([]*jwa.JWK, error) { return []*jwa.JWK{privateKey.JWK}, nil },
	})
	publishedKeys := jwk.NewSource(jwk.SourceConfig{
		Fetch: func(_ context.Context) ([]*jwa.JWK, error) { return []*jwa.JWK{publicKey.JWK}, nil },
	})

	producer := jwt.NewProducer(jwt.ProducerConfig{
		Plugins: []jwt.ProducerPlugin{jws.NewSourcedRSASigner(issuerKeys, jws.RS256)},
	})

	token, err := producer.Issue(ctx, map[string]any{"role": "admin"}, nil)
	if err != nil {
		panic(err)
	}

	recipient := jwt.NewRecipient(jwt.RecipientConfig{
		Plugins: []jwt.RecipientPlugin{jws.NewSourcedRSAVerifier(publishedKeys, jws.RS256)},
	})

	var claims map[string]any

	err = recipient.Consume(ctx, token, &claims)
	if err != nil {
		panic(err)
	}

	fmt.Println(claims["role"])
	// Output: admin
}
