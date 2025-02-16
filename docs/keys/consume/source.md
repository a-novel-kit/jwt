---
title: JWK Sources
icon: material-symbols:data-object-rounded
category:
  - keys
---

# JWK Sources

## Use sources

Sources are a powerful way to automatically handle your keys from a provider that implements keys rotation. A
Key Source supports fetching multiple keys at once, and caching them to lower resources consumption (keys don't have to
be recomputed from their serialized form each time).

To build a source, you first need a fetcher. This is a method that will be executed periodically to retrieve
a fresh set of keys. The keys MUST be deserialized into the generic `jwa.JWK` format.

```go
package main

import (
	"context"
	"encoding/json"
	"github.com/a-novel-kit/jwt/jwa"
	"net/http"
)

// Remote URL that serves your keys.
var remoteURL string

// Example implementation with net/http.
func httpKeysFetcher(ctx context.Context) ([]*jwa.JWK, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, remoteURL, nil)

	resp, _ := http.DefaultClient.Do(req)
	defer resp.Body.Close()

	var out []*jwa.JWK
	_ = json.NewDecoder(resp.Body).Decode(&out)

	return out, nil
}
```

::: warning
The sources currently provided only support one type of key. It is important that your fetcher filters only key
that match the algorithm you are looking for, otherwise retrieving the key will fail.
:::

Once you have a source set, you can consume its keys in 2 ways;

```go
package main

import (
	"context"
	"github.com/a-novel-kit/jwt/jwk"
)

func main() {
	var source *jwk.Source[T]

	// Returns every available keys, in order.
	keys, _ := source.List(context.Background())

	// Or use a key ID to retrieve a specific key.
	// If the KID is empty, this returns the first key
	// in the list.
	key, _ := source.Get(context.Background(), "key-id")
}
```

### Symmetric keys

::: tabs

@tab AES (CEK)

```go
package main

import (
	"github.com/a-novel-kit/jwt/jwa"
	"github.com/a-novel-kit/jwt/jwk"
	"time"
)

func main() {
	// Method to retrieve keys into their generic JSON
	// representation. See example above.
	var fetcher jwk.KeysFetcher

	config := jwk.SourceConfig{
		CacheDuration: time.Hour,
        Fetch:       fetcher,
	}

	source := jwk.NewAESSource(config, jwk.A128CBC)
}
```

Available presets for use as Content-Encryption Keys (CEK) are:

| Preset        | Target "enc"  |
| ------------- | ------------- |
| `jwk.A128CBC` | A128CBC-HS256 |
| `jwk.A192CBC` | A192CBC-HS384 |
| `jwk.A256CBC` | A256CBC-HS512 |
| `jwk.A128GCM` | A128GCM       |
| `jwk.A192GCM` | A192GCM       |
| `jwk.A256GCM` | A256GCM       |

@tab AES (KEK)

```go
package main

import (
	"github.com/a-novel-kit/jwt/jwa"
	"github.com/a-novel-kit/jwt/jwk"
	"time"
)

func main() {
	// Method to retrieve keys into their generic JSON
	// representation. See example above.
	var fetcher jwk.KeysFetcher

	config := jwk.SourceConfig{
		CacheDuration: time.Hour,
		Fetch:       fetcher,
	}

	source := jwk.NewAESSource(config, jwk.A128KW)
}
```

Available presets for use as Key-Encryption Keys (KEK) are:

| Preset          | Target "alg" |
| --------------- | ------------ |
| `jwk.A128KW`    | A128KW       |
| `jwk.A192KW`    | A192KW       |
| `jwk.A256KW`    | A256KW       |
| `jwk.A128GCMKW` | A128GCMKW    |
| `jwk.A192GCMKW` | A192GCMKW    |
| `jwk.A256GCMKW` | A256GCMKW    |

@tab HMAC (Sig)

```go
package main

import (
	"github.com/a-novel-kit/jwt/jwa"
	"github.com/a-novel-kit/jwt/jwk"
	"time"
)

func main() {
	// Method to retrieve keys into their generic JSON
	// representation. See example above.
	var fetcher jwk.KeysFetcher

	config := jwk.SourceConfig{
		CacheDuration: time.Hour,
		Fetch:       fetcher,
	}

	source := jwk.NewHMACSource(config, jwk.HS256)
}
```

Available presets for use as Signature keys are:

| Preset      | Target "alg" |
| ----------- | ------------ |
| `jwk.HS256` | HS256        |
| `jwk.HS384` | HS384        |
| `jwk.HS512` | HS512        |

:::

### Asymmetric keys

::: tabs

@tab ECDH (Key Agr)

```go
package main

import (
	"github.com/a-novel-kit/jwt/jwa"
	"github.com/a-novel-kit/jwt/jwk"
	"time"
)

func main() {
	// Method to retrieve keys into their generic JSON
	// representation. See example above.
	var fetcher jwk.KeysFetcher

	config := jwk.SourceConfig{
		CacheDuration: time.Hour,
		Fetch:       fetcher,
	}

	// Beware, as private and public keys are 2 different forms,
	// both sources will require their own fetcher / config.
	privateSource := jwk.NewECDHPrivateSource(config)
	publicSource := jwk.NewECDHPublicSource(config)
}
```

@tab ECDSA (Sig)

```go
package main

import (
	"github.com/a-novel-kit/jwt/jwa"
	"github.com/a-novel-kit/jwt/jwk"
	"time"
)

func main() {
	// Method to retrieve keys into their generic JSON
	// representation. See example above.
	var fetcher jwk.KeysFetcher

	config := jwk.SourceConfig{
		CacheDuration: time.Hour,
		Fetch:       fetcher,
	}

	// Beware, as private and public keys are 2 different forms,
	// both sources will require their own fetcher / config.
	privateSource := jwk.NewECDSAPrivateSource(config, jwk.ES256)
	publicSource := jwk.NewECDSAPublicSource(config, jwk.ES256)
}
```

Available presets for use as Signature keys are:

| Preset      | Target "alg" |
| ----------- | ------------ |
| `jwk.ES256` | ES256        |
| `jwk.ES384` | ES384        |
| `jwk.ES512` | ES512        |

@tab ED25519 (Sig)

```go
package main

import (
	"github.com/a-novel-kit/jwt/jwa"
	"github.com/a-novel-kit/jwt/jwk"
	"time"
)

func main() {
	// Method to retrieve keys into their generic JSON
	// representation. See example above.
	var fetcher jwk.KeysFetcher

	config := jwk.SourceConfig{
		CacheDuration: time.Hour,
		Fetch:       fetcher,
	}

	// Beware, as private and public keys are 2 different forms,
	// both sources will require their own fetcher / config.
	privateSource := jwk.NewED25519PrivateSource(config)
	publicSource := jwk.NewED25519PublicSource(config)
}
```

@tab RSA (Sig)

```go
package main

import (
	"github.com/a-novel-kit/jwt/jwa"
	"github.com/a-novel-kit/jwt/jwk"
	"time"
)

func main() {
	// Method to retrieve keys into their generic JSON
	// representation. See example above.
	var fetcher jwk.KeysFetcher

	config := jwk.SourceConfig{
		CacheDuration: time.Hour,
		Fetch:       fetcher,
	}

	// Beware, as private and public keys are 2 different forms,
	// both sources will require their own fetcher / config.
	privateSource := jwk.NewRSAPrivateSource(config, jwk.RS256)
	publicSource := jwk.NewRSAPublicSource(config, jwk.RS256)
}
```

Available presets for use as Signature keys are:

| Preset      | Target "alg" |
| ----------- | ------------ |
| `jwk.RS256` | RS256        |
| `jwk.RS384` | RS384        |
| `jwk.RS512` | RS512        |
| `jwk.PS256` | PS256        |
| `jwk.PS384` | PS384        |
| `jwk.PS512` | PS512        |

@tab RSA (Key Enc)

```go
package main

import (
	"github.com/a-novel-kit/jwt/jwa"
	"github.com/a-novel-kit/jwt/jwk"
	"time"
)

func main() {
	// Method to retrieve keys into their generic JSON
	// representation. See example above.
	var fetcher jwk.KeysFetcher

	config := jwk.SourceConfig{
		CacheDuration: time.Hour,
		Fetch:       fetcher,
	}

	// Beware, as private and public keys are 2 different forms,
	// both sources will require their own fetcher / config.
	privateSource := jwk.NewRSAPrivateSource(config, jwk.RSAOAEP256)
	publicSource := jwk.NewRSAPublicSource(config, jwk.RSAOAEP256)
}
```

Available presets for use as Key-Encryption keys are:

| Preset           | Target "alg" |
| ---------------- | ------------ |
| ⚠️ `jwk.RSAOAEP` | RSAOAEP      |
| `jwk.RSAOAEP256` | RSAOAEP256   |

::: danger
`RSA-OAEP` without sha256 is deprecated, as it relies on the broken SHA1 algorithm. It is still available for
compatibility reasons, but should not be used in new applications.

See [this post for explanation](https://crypto.stackexchange.com/a/3691)
:::
