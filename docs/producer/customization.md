---
outline: deep
---

# Advanced customization

The Producer interface gives you tools to customize the output of the token, independently of the plugins.

## Header configuration

```go
package main

import (
	"context"
	"github.com/a-novel-kit/jwt"
	"github.com/a-novel-kit/jwt/jwa"
)

func main() {
	producer := jwt.NewProducer(jwt.ProducerConfig{
		Header: jwt.HeaderProducerConfig{
			// JWT is a standard that targets an optimal representation in
			// order to save space.
			// Both fields below are optional, so they are ignored by default.
			Typ: jwa.TypJOSE,
            Cty: jwa.CtyJWT,

			// Duplicate Target information in the header.
			TargetConfig: jwt.TargetConfig{
				Issuer: "Bob",
				Audience: "Alice",
				Subject: "auth",
            },
        },
    })
}
```

Header configuration is fairly limited, as most plugins depend on it.

### Crit header parameter

An important feature you might want to use is the `crit` header. This header extends the range of recognized header
fields, and makes sure those extensions are understood by the recipient.

```go
package main

import (
	"context"
	"github.com/a-novel-kit/jwt"
	"github.com/a-novel-kit/jwt/jwa"
)

func main() {
	producer := jwt.NewProducer(jwt.ProducerConfig{
		Header: jwt.HeaderProducerConfig{
            Crit: []string{"ext1", "ext2"},
        },
    })
	claims := map[string]any{"foo": "bar"}
	headers := map[string]any{"ext1": "value1", "ext2": "value2"}

	// Custom header data is REQUIRED.
	token, _ := producer.Issue(context.Background(), claims, headers)
}
```

::: warning
**EVERY** field listed under the `crit` header **MUST** be present in the header, and understood.

Attempting to generate a token without providing a field listed under the `crit` header will fail.

Similarly, consuming a token that lacks one of the `crit` headers will fail, using this library.
:::

## Claims configuration

Claims configuration is a bit different, as it does not have an impact on the JWT process. Still, the original
specification defines standard claims fields, that can be checked once all operations have been performed.

```go
package main

import (
	"context"
	"github.com/a-novel-kit/jwt"
	"github.com/a-novel-kit/jwt/jwa"
	"time"
)

func main() {
	producer := jwt.NewProducer(jwt.ProducerConfig{})

	claims, _ := jwt.NewBasicClaims(
		map[string]any{"foo": "bar"},
		jwt.ClaimsProducerConfig{
            // Provide information about the intended target of the token.
            TargetConfig: jwt.TargetConfig{
                Issuer:   "Bob",
                Audience: "Alice",
                Subject:  "auth",
            },
            // Optional, sets an expiration for the token claims.
            TTL: time.Hour,
        },
    )

	// Custom header data is REQUIRED.
	token, _ := producer.Issue(context.Background(), claims, nil)
}
```

This builder is purely optional, as you can still pass standard fields directly from your custom claims object.
However, it has the benefit of setting most fields automatically, using the correct format.

Apart from what is explicitly declared in the configuration, this helper:

- Sets a token ID (`jti`)
- Sets date fields (`nbf` and `iat`) with a properly formatted timestamp
