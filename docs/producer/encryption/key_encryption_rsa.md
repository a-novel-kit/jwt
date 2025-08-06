---
outline: deep
---

# Key Encryption (RSAES)

Key Encryption with RSAES uses a kind of "reverse" encryption. In this mode, the holder of the private key is the
recipient, not the producer. The recipient shares a public key, that the producer can use to encrypt the CEK. Then,
only the recipient with the private key will be able to decrypt the CEK and access the payload.

```go
package main

import (
	"crypto/rsa"
	"github.com/a-novel-kit/jwt/jwe/jwek"
)

func main() {
	// Once encrypted, the producer will not be able
	// to retrieve the CEK anymore from the token.
	var cek []byte

	// Public key shared by the recipient.
	var publicKey *rsa.PublicKey

	keyManager := jwek.NewRSAOAEPKeyEncManager(
		&jwek.RSAOAEPKeyEncManagerConfig{
            CEK: cek, EncKey: publicKey,
        },
        jwek.RSAOAEP256,
	)
}
```

Available presets:

| Preset            | Target "alg" |
| ----------------- | ------------ |
| ⚠️ `jwek.RSAOAEP` | RSA-OAEP     |
| `jwek.RSAOAEP256` | RSA-OAEP-256 |

::: danger
`RSA-OAEP` without sha256 is deprecated, as it relies on the broken SHA1 algorithm. It is still available for
compatibility reasons, but should not be used in new applications.

See [this post for explanation](https://crypto.stackexchange.com/a/3691)
:::
