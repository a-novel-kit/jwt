---
title: Verify Token (JWS)
icon: material-symbols:verified-outline-rounded
category:
  - recipient
  - signature
---

# Verify tokens

Per the [specification](https://datatracker.ietf.org/doc/html/rfc7515):

> JSON Web Signature (JWS) represents content secured with digital
> signatures or Message Authentication Codes (MACs) using JSON-based
> data structures. Cryptographic algorithms and identifiers for use
> with this specification are described in the separate JSON Web
> Algorithms (JWA) specification and an IANA registry defined by that
> specification. Related encryption capabilities are described in the
> separate JSON Web Encryption (JWE) specification.

::: info Workflow

_Bob sends data to Alice. Alice then forwards it to Bob friend's John. John needs a way to ensure that the data packet
he received from Alice was indeed created by Bob._

_When Bob created the packet, he appended a signature to it, using a private key. A signature
is computed from the data in the packet and the private key. Bob shares a public version of the key used to create
the signature. Then, using this public key, John can apply it against the signature and the data packet he received._

_If the data packet has been modified by Alice, or the signature was not created using Bob's private key, then the
authentication will fail. If it works, John can be assured the data packet was created by no other than Bob itself
(or at least, someone that has access to its private key)._

:::

Every signature algorithm is based on a private/public key pair. Most algorithms use asymmetric keys (where the
public key only contains a subset of the private key information): the private key is kept secret to
the producer, while the recipients can only access the public key. Some algorithms, however, use symmetric keys
(like HMAC): in this case, the same key is shared by the producer and recipient, and both can either sign or verify
tokens.

::: tabs

@tab HMAC

```go
package main

import (
	"context"
	"github.com/a-novel-kit/jwt"
	"github.com/a-novel-kit/jwt/jws"
)

func main() {
	// HMAC Signatures validation require a symmetric HMAC key.
	// This secret key should be shared by the producer.
	var secretKey []byte

	// The raw token received from the producer.
	var token string

	signer := jws.NewHMACVerifier(secretKey, jws.HS256)
	recipient := jwt.NewRecipient(jwt.RecipientConfig{
		Plugins: []jwt.RecipientPlugin{signer},
	})

	var claims map[string]any
	_ := recipient.Consume(context.Background(), token, &claims)
}
```

Available presets for HMAC signatures are:

| Preset      | Target "alg" |
| ----------- | ------------ |
| `jws.HS256` | HS256        |
| `jws.HS384` | HS384        |
| `jws.HS512` | HS512        |

@tab RSA

```go
package main

import (
	"context"
	"crypto/rsa"
	"github.com/a-novel-kit/jwt"
	"github.com/a-novel-kit/jwt/jws"
)

func main() {
	// RSA Signatures validation require a rsa Public key.
	// This public key should be shared by the producer.
	var publicKey *rsa.PublicKey

	// The raw token received from the producer.
	var token string

	signer := jws.NewRSAVerifier(publicKey, jws.RS256)
	recipient := jwt.NewRecipient(jwt.RecipientConfig{
		Plugins: []jwt.RecipientPlugin{signer},
	})

	var claims map[string]any
	_ := recipient.Consume(context.Background(), token, &claims)
}
```

Available presets for RSA signatures are:

| Preset      | Target "alg" |
| ----------- | ------------ |
| `jws.RS256` | RS256        |
| `jws.RS384` | RS384        |
| `jws.RS512` | RS512        |

@tab RSA PSS

```go
package main

import (
	"context"
	"crypto/rsa"
	"github.com/a-novel-kit/jwt"
	"github.com/a-novel-kit/jwt/jws"
)

func main() {
	// RSA PSS Signatures validation require a rsa Public key.
	// This public key should be shared by the producer.
	var publicKey *rsa.PublicKey

	// The raw token received from the producer.
	var token string

	signer := jws.NewRSAPSSVerifier(publicKey, jws.PS256)
	recipient := jwt.NewRecipient(jwt.RecipientConfig{
		Plugins: []jwt.RecipientPlugin{signer},
	})

	var claims map[string]any
	_ := recipient.Consume(context.Background(), token, &claims)
}
```

Available presets for RSA PSS signatures are:

| Preset      | Target "alg" |
| ----------- | ------------ |
| `jws.PS256` | PS256        |
| `jws.PS384` | PS384        |
| `jws.PS512` | PS512        |

@tab ECDSA

```go
package main

import (
	"context"
	"crypto/ecdsa"
	"github.com/a-novel-kit/jwt"
	"github.com/a-novel-kit/jwt/jws"
)

func main() {
	// ECDSA Signatures validation require a ecdsa Public key.
	// This public key should be shared by the producer.
	var publicKey *ecdsa.PublicKey

	// The raw token received from the producer.
	var token string

	signer := jws.NewECDSAVerifier(publicKey, jws.ES256)
	recipient := jwt.NewRecipient(jwt.RecipientConfig{
		Plugins: []jwt.RecipientPlugin{signer},
	})

	var claims map[string]any
	_ := recipient.Consume(context.Background(), token, &claims)
}
```

Available presets for ECDSA signatures are:

| Preset      | Target "alg" |
| ----------- | ------------ |
| `jws.ES256` | ES256        |
| `jws.ES384` | ES384        |
| `jws.ES512` | ES512        |

@tab ED25519

```go
package main

import (
	"context"
	"crypto/ed25519"
	"github.com/a-novel-kit/jwt"
	"github.com/a-novel-kit/jwt/jws"
)

func main() {
	// ED25519 Signatures validation require a ed25519 Public key.
	// This public key should be shared by the producer.
	var publicKey ed25519.PublicKey

	// The raw token received from the producer.
	var token string

	signer := jws.NewED25519Verifier(publicKey)
	recipient := jwt.NewRecipient(jwt.RecipientConfig{
		Plugins: []jwt.RecipientPlugin{signer},
	})

	var claims map[string]any
	_ := recipient.Consume(context.Background(), token, &claims)
}
```

:::

## Using auto-sourcing

Passing keys manually and creating a new signer for each secret key can be cumbersome. To avoid this, you can use an
alternate version that relies on a [dynamic source](../keys/consume/source.md) of keys.

::: tabs

@tab HMAC

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

	// The raw token received from the producer.
	var token string

	signer := jws.NewSourcedHMACVerifier(source, jws.HS256)
	recipient := jwt.NewRecipient(jwt.RecipientConfig{
		Plugins: []jwt.RecipientPlugin{signer},
	})

	var claims map[string]any
	_ := recipient.Consume(context.Background(), token, &claims)
}
```

Available presets for HMAC signatures are:

| Preset      | Target "alg" | Source preset |
| ----------- | ------------ | ------------- |
| `jws.HS256` | HS256        | `jwk.HS256`   |
| `jws.HS384` | HS384        | `jwk.HS384`   |
| `jws.HS512` | HS512        | `jwk.HS512`   |

@tab RSA

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
	source := jwk.NewRSAPublicSource(config, jwk.RS256)

	// The raw token received from the producer.
	var token string

	signer := jws.NewSourcedRSAVerifier(source, jws.RS256)
	recipient := jwt.NewRecipient(jwt.RecipientConfig{
		Plugins: []jwt.RecipientPlugin{signer},
	})

	var claims map[string]any
	_ := recipient.Consume(context.Background(), token, &claims)
}
```

Available presets for RSA signatures are:

| Preset      | Target "alg" | Source preset |
| ----------- | ------------ | ------------- |
| `jws.RS256` | RS256        | `jwk.RS256`   |
| `jws.RS384` | RS384        | `jwk.RS384`   |
| `jws.RS512` | RS512        | `jwk.RS512`   |

@tab RSA PSS

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
	source := jwk.NewRSAPublicSource(config, jwk.PS256)

	// The raw token received from the producer.
	var token string

	signer := jws.NewSourcedRSAPSSVerifier(source, jws.PS256)
	recipient := jwt.NewRecipient(jwt.RecipientConfig{
		Plugins: []jwt.RecipientPlugin{signer},
	})

	var claims map[string]any
	_ := recipient.Consume(context.Background(), token, &claims)
}
```

Available presets for RSA PSS signatures are:

| Preset      | Target "alg" | Source preset |
| ----------- | ------------ | ------------- |
| `jws.PS256` | PS256        | `jwk.PS256`   |
| `jws.PS384` | PS384        | `jwk.PS384`   |
| `jws.PS512` | PS512        | `jwk.PS512`   |

@tab ECDSA

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
	source := jwk.NewECDSAPublicSource(config, jwk.ES256)

	// The raw token received from the producer.
	var token string

	signer := jws.NewSourcedECDSAVerifier(source, jws.ES256)
	recipient := jwt.NewRecipient(jwt.RecipientConfig{
		Plugins: []jwt.RecipientPlugin{signer},
	})

	var claims map[string]any
	_ := recipient.Consume(context.Background(), token, &claims)
}
```

Available presets for ECDSA signatures are:

| Preset      | Target "alg" | Source preset |
| ----------- | ------------ | ------------- |
| `jws.ES256` | ES256        | `jwk.ES256`   |
| `jws.ES384` | ES384        | `jwk.ES384`   |
| `jws.ES512` | ES512        | `jwk.ES512`   |

@tab ED25519

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
	source := jwk.NewED25519PublicSource(config)

	// The raw token received from the producer.
	var token string

	signer := jws.NewSourcedED25519Verifier(source)
	recipient := jwt.NewRecipient(jwt.RecipientConfig{
		Plugins: []jwt.RecipientPlugin{signer},
	})

	var claims map[string]any
	_ := recipient.Consume(context.Background(), token, &claims)
}
```

:::
