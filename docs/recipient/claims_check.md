---
title: Claims check
icon: material-symbols:frame-inspect-rounded
category:
  - recipient
---

# Claims check

Claims check is a custom deserializer that validates common claims before deserializing them.

```go
package main

import (
	"context"
	"github.com/a-novel-kit/jwt"
	"github.com/a-novel-kit/jwt/jwp"
)

func main() {
	// JWT received from somewhere.
	var token string

	recipient := jwt.NewRecipient(jwt.RecipientConfig{
		Deserializer: jwp.NewClaimsChecker(&jwp.ClaimsCheckerConfig{}),
	})

	// Common claims will be checked before deserialization, if present.
	var claims map[string]any
	_ = recipient.Consume(context.Background(), token, &claims)
}
```

The default configuration:

- Checks `"nbf"` (if present), and rejects the token if it is in the future.
- Checks `"exp"` (if present), and rejects the token if it is in the past.

## Custom configuration

```go
package main

import (
	"context"
	"encoding/json"
	"github.com/a-novel-kit/jwt"
	"github.com/a-novel-kit/jwt/jwp"
	"time"
)

func main() {
	// JWT received from somewhere.
	var token string

	recipient := jwt.NewRecipient(jwt.RecipientConfig{
		Deserializer: jwp.NewClaimsChecker(&jwp.ClaimsCheckerConfig{
			// Ensure target information in the claims match.
			Target: &jwt.TargetConfig{
				Issuer:   "Bob",
				Audience: "Alice",
				Subject:  "auth",
			},
			// Allow some leeway when checking dates.
			Leeway: 5 * time.Minute,
			// Fail if no expiration date is present.
			RequireExpiration: true,

			// Set up your own deserializer. Uses json.Unmarshal by default.
			Deserializer: json.Unmarshal,
		}),
	})

	// Common claims will be checked before deserialization, if present.
	var claims map[string]any
	_ = recipient.Consume(context.Background(), token, &claims)
}
```
