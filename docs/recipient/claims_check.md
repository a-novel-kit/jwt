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

The default configuration doe nothing on its own, except deserializing. You can add checks from the config.

## Configure checks

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
			Checks: []jwp.ClaimsCheck{
				jwp.NewClaimsCheckTimestamp(5*time.Minute, true),
				jwp.NewClaimsCheckTarget(jwt.TargetConfig{
					Issuer:   "Bob",
					Audience: "Alice",
					Subject:  "auth",
				}),
			},
		}),
	})

	// Common claims will be checked before deserialization, if present.
	var claims map[string]any
	_ = recipient.Consume(context.Background(), token, &claims)
}
```

### NewClaimsCheckTimestamp

Checks the `nbf` and `exp` claims against the current time.

```go
// First argument is a leeway, allowing margin of error
// when checking for timestamp validity.
jwp.NewClaimsCheckTimestamp(5*time.Minute, false)
```

By default, this checks allows token with no expiration date. You can change this behavior by setting the flag
argument to true:

```go
jwp.NewClaimsCheckTimestamp(5*time.Minute, true)
```

### NewClaimsCheckTarget

Force the target in the claims to match the given configuration.

```go
jwp.NewClaimsCheckTarget(jwt.TargetConfig{...})
```

### Custom checks

You can create your own checks by implementing the `ClaimsCheck` interface.

```go
package main

import "github.com/a-novel-kit/jwt/jwa"

type ClaimsCheck interface {
	CheckClaims(claims *jwa.Claims) error
}
```
