---
title: Key Wrapping
icon: material-symbols:inventory-2-outline
category:
  - recipient
  - encryption
  - key sharing
---

# Key Wrapping

Key Wrapping shares a symmetric key, kind of like [Direct Key Encryption](./direct.md). However, instead of using
the shared key as the CEK, it uses it to wrap the actual CEK, so that only a recipient with the correct KEK can
unwrap the CEK and decrypt the token.

::: tabs

@tab AES KW

```go
package main

import "github.com/a-novel-kit/jwt/jwe/jwek"

func main() {
	// The KEK is shared directly between the producer and the recipient.
	var kek []byte

	keyDecoder := jwek.NewAESKWDecoder(
		&jwek.AESKWDecoderConfig{WrapKey: kek},
		jwek.A128KW,
	)
}
```

Available presets:

| Preset        | Target "alg" |
|---------------|--------------|
| `jwek.A128KW` | A128KW       |
| `jwek.A192KW` | A192KW       |
| `jwek.A256KW` | A256KW       |

@tab AES-GCM KW

```go
package main

import "github.com/a-novel-kit/jwt/jwe/jwek"

func main() {
	// The KEK is shared directly between the producer and the recipient.
	var kek []byte

	keyDecoder := jwek.NewAESGCMKWDecoder(
		&jwek.AESKWDecoderConfig{WrapKey: kek},
		jwek.A128GCMKW,
	)
}
```

Available presets:

| Preset           | Target "alg" |
|------------------|--------------|
| `jwek.A128GCMKW` | A128GCMKW    |
| `jwek.A192GCMKW` | A192GCMKW    |
| `jwek.A256GCMKW` | A256GCMKW    |

:::
