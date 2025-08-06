---
outline: deep
---

# Sign tokens

Per the [specification](https://datatracker.ietf.org/doc/html/rfc7515):

> JSON Web Signature (JWS) represents content secured with digital
> signatures or Message Authentication Codes (MACs) using JSON-based
> data structures. Cryptographic algorithms and identifiers for use
> with this specification are described in the separate JSON Web
> Algorithms (JWA) specification and an IANA registry defined by that
> specification. Related encryption capabilities are described in the
> separate JSON Web Encryption (JWE) specification.

Every signature algorithm is based on a private/public key pair. Most algorithms use asymmetric keys (where the
public key only contains a subset of the private key information): the private key is kept secret to
the producer, while the recipients can only access the public key. Some algorithms, however, use symmetric keys
(like HMAC): in this case, the same key is shared by the producer and recipient, and both can either sign or verify
tokens.

::: tabs

== HMAC

```go
package main

import (
	"context"
	"github.com/a-novel-kit/jwt"
	"github.com/a-novel-kit/jwt/jws"
)

func main() {
	// HMAC Signatures require a symmetric HMAC key.
	// Refer to the JWK package for hints to generate one.
	var secretKey []byte

	signer := jws.NewHMACSigner(secretKey, jws.HS256)
	producer := jwt.NewProducer(jwt.ProducerConfig{
		Plugins: []jwt.ProducerPlugin{signer},
	})

	claims := map[string]any{"foo": "bar"}
	token, _ := producer.Issue(context.Background(), claims, nil)
}
```

Available presets for HMAC signatures are:

| Preset      | Target "alg" |
| ----------- | ------------ |
| `jws.HS256` | HS256        |
| `jws.HS384` | HS384        |
| `jws.HS512` | HS512        |

== RSA

```go
package main

import (
	"context"
	"crypto/rsa"
	"github.com/a-novel-kit/jwt"
	"github.com/a-novel-kit/jwt/jws"
)

func main() {
	// RSA Signatures require a rsa Private key.
	// Refer to the JWK package for hints to generate one.
	var secretKey *rsa.PrivateKey

	signer := jws.NewRSASigner(secretKey, jws.RS256)
	producer := jwt.NewProducer(jwt.ProducerConfig{
		Plugins: []jwt.ProducerPlugin{signer},
	})

	claims := map[string]any{"foo": "bar"}
	token, _ := producer.Issue(context.Background(), claims, nil)
}
```

Available presets for RSA signatures are:

| Preset      | Target "alg" |
| ----------- | ------------ |
| `jws.RS256` | RS256        |
| `jws.RS384` | RS384        |
| `jws.RS512` | RS512        |

== RSA PSS

```go
package main

import (
	"context"
	"crypto/rsa"
	"github.com/a-novel-kit/jwt"
	"github.com/a-novel-kit/jwt/jws"
)

func main() {
	// RSA PSS Signatures require a rsa Private key.
	// Refer to the JWK package for hints to generate one.
	var secretKey *rsa.PrivateKey

	signer := jws.NewRSAPSSSigner(secretKey, jws.PS256)
	producer := jwt.NewProducer(jwt.ProducerConfig{
		Plugins: []jwt.ProducerPlugin{signer},
	})

	claims := map[string]any{"foo": "bar"}
	token, _ := producer.Issue(context.Background(), claims, nil)
}
```

Available presets for RSA PSS signatures are:

| Preset      | Target "alg" |
| ----------- | ------------ |
| `jws.PS256` | PS256        |
| `jws.PS384` | PS384        |
| `jws.PS512` | PS512        |

== ECDSA

```go
package main

import (
	"context"
	"crypto/ecdsa"
	"github.com/a-novel-kit/jwt"
	"github.com/a-novel-kit/jwt/jws"
)

func main() {
	// ECDSA Signatures require a ecdsa Private key.
	// Refer to the JWK package for hints to generate one.
	var secretKey *ecdsa.PrivateKey

	signer := jws.NewECDSASigner(secretKey, jws.ES256)
	producer := jwt.NewProducer(jwt.ProducerConfig{
		Plugins: []jwt.ProducerPlugin{signer},
	})

	claims := map[string]any{"foo": "bar"}
	token, _ := producer.Issue(context.Background(), claims, nil)
}
```

Available presets for ECDSA signatures are:

| Preset      | Target "alg" |
| ----------- | ------------ |
| `jws.ES256` | ES256        |
| `jws.ES384` | ES384        |
| `jws.ES512` | ES512        |

== ED25519

```go
package main

import (
	"context"
	"crypto/ed25519"
	"github.com/a-novel-kit/jwt"
	"github.com/a-novel-kit/jwt/jws"
)

func main() {
	// ED25519 Signatures require a ed25519 Private key.
	// Refer to the JWK package for hints to generate one.
	var secretKey ed25519.PrivateKey

	signer := jws.NewED25519Signer(secretKey)
	producer := jwt.NewProducer(jwt.ProducerConfig{
		Plugins: []jwt.ProducerPlugin{signer},
	})

	claims := map[string]any{"foo": "bar"}
	token, _ := producer.Issue(context.Background(), claims, nil)
}
```

:::

## Using auto-sourcing

Passing keys manually and creating a new signer for each secret key can be cumbersome. To avoid this, you can use an
alternate version that relies on a [dynamic source](../keys/consume/source.md) of keys.

::: tabs

== HMAC

```go
package main

import (
	"context"
	"github.com/a-novel-kit/jwt"
	"github.com/a-novel-kit/jwt/jwk"
	"github.com/a-novel-kit/jwt/jws"
)

func main() {
	// See JWK documentation for how to configure the source.
	// Preset for the source MUST match those of the signer.
	source := jwk.NewHMACSource(config, jwk.HS256)

	signer := jws.NewSourcedHMACSigner(source, jws.HS256)
	producer := jwt.NewProducer(jwt.ProducerConfig{
		Plugins: []jwt.ProducerPlugin{signer},
	})

	claims := map[string]any{"foo": "bar"}
	token, _ := producer.Issue(context.Background(), claims, nil)
}
```

Available presets for HMAC signatures are:

| Preset      | Target "alg" | Source preset |
| ----------- | ------------ | ------------- |
| `jws.HS256` | HS256        | `jwk.HS256`   |
| `jws.HS384` | HS384        | `jwk.HS384`   |
| `jws.HS512` | HS512        | `jwk.HS512`   |

== RSA

```go
package main

import (
	"context"
	"github.com/a-novel-kit/jwt"
	"github.com/a-novel-kit/jwt/jwk"
	"github.com/a-novel-kit/jwt/jws"
)

func main() {
	// See JWK documentation for how to configure the source.
	// Preset for the source MUST match those of the signer.
	source := jwk.NewRSAPrivateSource(config, jwk.RS256)

	signer := jws.NewSourcedRSASigner(source, jws.RS256)
	producer := jwt.NewProducer(jwt.ProducerConfig{
		Plugins: []jwt.ProducerPlugin{signer},
	})

	claims := map[string]any{"foo": "bar"}
	token, _ := producer.Issue(context.Background(), claims, nil)
}
```

Available presets for RSA signatures are:

| Preset      | Target "alg" | Source preset |
| ----------- | ------------ | ------------- |
| `jws.RS256` | RS256        | `jwk.RS256`   |
| `jws.RS384` | RS384        | `jwk.RS384`   |
| `jws.RS512` | RS512        | `jwk.RS512`   |

== RSA PSS

```go
package main

import (
	"context"
	"github.com/a-novel-kit/jwt"
	"github.com/a-novel-kit/jwt/jwk"
	"github.com/a-novel-kit/jwt/jws"
)

func main() {
	// See JWK documentation for how to configure the source.
	// Preset for the source MUST match those of the signer.
	source := jwk.NewRSAPrivateSource(config, jwk.PS256)

	signer := jws.NewSourcedRSAPSSSigner(source, jws.PS256)
	producer := jwt.NewProducer(jwt.ProducerConfig{
		Plugins: []jwt.ProducerPlugin{signer},
	})

	claims := map[string]any{"foo": "bar"}
	token, _ := producer.Issue(context.Background(), claims, nil)
}
```

Available presets for RSA PSS signatures are:

| Preset      | Target "alg" | Source preset |
| ----------- | ------------ | ------------- |
| `jws.PS256` | PS256        | `jwk.PS256`   |
| `jws.PS384` | PS384        | `jwk.PS384`   |
| `jws.PS512` | PS512        | `jwk.PS512`   |

== ECDSA

```go
package main

import (
	"context"
	"github.com/a-novel-kit/jwt"
	"github.com/a-novel-kit/jwt/jwk"
	"github.com/a-novel-kit/jwt/jws"
)

func main() {
	// See JWK documentation for how to configure the source.
	// Preset for the source MUST match those of the signer.
	source := jwk.NewECDSAPrivateSource(config, jwk.ES256)

	signer := jws.NewSourcedECDSASigner(source, jws.ES256)
	producer := jwt.NewProducer(jwt.ProducerConfig{
		Plugins: []jwt.ProducerPlugin{signer},
	})

	claims := map[string]any{"foo": "bar"}
	token, _ := producer.Issue(context.Background(), claims, nil)
}
```

Available presets for ECDSA signatures are:

| Preset      | Target "alg" | Source preset |
| ----------- | ------------ | ------------- |
| `jws.ES256` | ES256        | `jwk.ES256`   |
| `jws.ES384` | ES384        | `jwk.ES384`   |
| `jws.ES512` | ES512        | `jwk.ES512`   |

== ED25519

```go
package main

import (
	"context"
	"github.com/a-novel-kit/jwt"
	"github.com/a-novel-kit/jwt/jwk"
	"github.com/a-novel-kit/jwt/jws"
)

func main() {
	// See JWK documentation for how to configure the source.
	// Preset for the source MUST match those of the signer.
	source := jwk.NewED25519PrivateSource(config)

	signer := jws.NewSourcedED25519Signer(source)
	producer := jwt.NewProducer(jwt.ProducerConfig{
		Plugins: []jwt.ProducerPlugin{signer},
	})

	claims := map[string]any{"foo": "bar"}
	token, _ := producer.Issue(context.Background(), claims, nil)
}
```

:::
