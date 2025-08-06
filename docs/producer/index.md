---
outline: deep
---

# Producing tokens

```go
package main

import (
	"context"
	"github.com/a-novel-kit/jwt"
)

func main() {
	producer := jwt.NewProducer(jwt.ProducerConfig{})
	claims := map[string]any{"foo": "bar"}
	token, _ := producer.Issue(context.Background(), claims, nil)
}
```

All it takes to issue a token is 3 simple steps:

- Create and configure a **Producer**
- Get your set of **claims**
- Boom, token created!

## Producer Plugins

The producer accepts a list of plugins as an input, to perform transformation of the token.

```go
package main

import (
	"context"
	"github.com/a-novel-kit/jwt"
)

func main() {
	producer := jwt.NewProducer(jwt.ProducerConfig{
		Plugins: []jwt.ProducerPlugin{...},
		// Sub-class of plugins that only affect the Header, without
		// performing any transformation on the claims.
		StaticPlugins: []ProducerStaticPlugin{...},
	})
	claims := map[string]any{"foo": "bar"}
	token, _ := producer.Issue(context.Background(), claims, nil)
}
```

Those plugins are executed sequentially, starting with the `StaticPlugins`, then the `Plugins`.

::: warning

While multiple static plugins can be supplied without much risk, it is generally recommended to use only a single
fully-fledged plugin.

Transformation operations can drastically change the shape of a token, often in incompatible
ways (think of the radically different structure of JWS and JWE tokens). Plus, most operations rely on information
stored in the same header fields. Both `"alg"` and `"enc"` headers, for example, can only accommodate a single
operation.

You may still supply more than one transforming plugin, but make sure you are fully aware of compatibility issues
before doing so.

:::

Use the `Plugins` field to set up common JWT operations:

- [JWS](./signature.md): authenticate the data in a token, without hiding it.
- [JWE](./encryption/index.md): encrypt the data in a token, to keep it confidential.
