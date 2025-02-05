---
title: Recipient
icon: material-symbols:mark-as-unread-outline-rounded
category:
  - recipient
---

# Consuming tokens

```go
package main

import (
	"context"
	"github.com/a-novel-kit/jwt"
)

func main() {
	// JWT received from somewhere.
	var token string

	recipient := jwt.NewRecipient(jwt.RecipientConfig{})

	var claims map[string]any
	_ = recipient.Consume(context.Background(), token, &claims)
}
```

All it takes to consume a token is 3 simple steps:

- Create and configure a **Recipient**
- Take your **token**
- Boom, content extracted!

## Recipient Plugins

The recipient accepts a list of plugins as an input. A plugin will try to extract the claims from a payload. If it
fails to recognize the token format, it will fail and pass the token to the next plugin. The resulting claim will be
the result of the first plugin to succeed.

```go
package main

import (
	"context"
	"github.com/a-novel-kit/jwt"
	"github.com/a-novel-kit/jwt/jws"
)

func main() {
	// JWT received from somewhere.
	var token string

	// We might not be sure about the signing algorithm used by the producer.
	// In this case, we can just provide multiple plugins, and see which one works.

	hmacVerifier := jws.NewHMACVerifier(...)
	ecdsaVerifier := jws.NewECDSAVerifier(...)

	recipient := jwt.NewRecipient(jwt.RecipientConfig{
		Plugins: []jwt.RecipientPlugin{hmacVerifier, ecdsaVerifier},
	})

	var claims map[string]any
	_ = recipient.Consume(context.Background(), token, &claims)
}
```

::: info

By default, if no plugin is supplied, the recipient will try to read the token as a raw token (unencrypted, unsigned
token with the `"alg"` header set to `"none"`).

Providing any plugin disables this possibility, so if you need you can restore it by manually adding
`jwt.NewDefaultRecipientPlugin()` to the plugins list.

:::

Use the `Plugins` field to set up common JWT operations:

- [JWS](./signature.md): authenticate the data in a token, without hiding it.
- [JWE](./encryption/README.md): encrypt the data in a token, to keep it confidential.
