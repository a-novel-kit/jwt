package jwt_test

import (
	"context"
	"fmt"
	"time"

	"github.com/a-novel-kit/jwt/v2"
	"github.com/a-novel-kit/jwt/v2/jwa"
	"github.com/a-novel-kit/jwt/v2/jwk"
	"github.com/a-novel-kit/jwt/v2/jwp"
	"github.com/a-novel-kit/jwt/v2/jws"
)

// Example signs a token with HMAC, then verifies it and validates its registered claims before
// decoding the payload.
func Example() {
	ctx := context.Background()

	key, err := jwk.GenerateHMAC(jwk.HS256)
	if err != nil {
		panic(err)
	}

	target := jwt.TargetConfig{Issuer: "accounts", Audience: jwa.Audience{"api"}, Subject: "user-123"}

	producer := jwt.NewProducer(jwt.ProducerConfig{
		Plugins: []jwt.ProducerPlugin{jws.NewHMACSigner(key.Key(), jws.HS256)},
	})

	claims, err := jwt.NewBasicClaims(map[string]any{"role": "admin"}, jwt.ClaimsProducerConfig{
		TargetConfig: target,
		TTL:          15 * time.Minute,
	})
	if err != nil {
		panic(err)
	}

	token, err := producer.Issue(ctx, claims, nil)
	if err != nil {
		panic(err)
	}

	checker := jwp.NewClaimsChecker(&jwp.ClaimsCheckerConfig{
		Checks: []jwp.ClaimsCheck{
			jwp.NewClaimsCheckTarget(target),
			jwp.NewClaimsCheckTimestamp(30*time.Second, true),
		},
	})

	recipient := jwt.NewRecipient(jwt.RecipientConfig{
		Deserializer: checker.Unmarshal,
		Plugins:      []jwt.RecipientPlugin{jws.NewHMACVerifier(key.Key(), jws.HS256)},
	})

	var payload map[string]any

	err = recipient.Consume(ctx, token, &payload)
	if err != nil {
		panic(err)
	}

	fmt.Println(payload["role"], payload["sub"])
	// Output: admin user-123
}
