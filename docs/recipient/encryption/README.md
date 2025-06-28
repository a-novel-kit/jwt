---
title: Decrypt Token (JWE)
icon: material-symbols:lock-open-right-outline-rounded
category:
  - recipient
  - encryption
---

# Decrypt Token (JWE)

Per the [specification](https://datatracker.ietf.org/doc/html/rfc7516):

> JSON Web Encryption (JWE) represents encrypted content using
> JSON-based data structures. Cryptographic algorithms and identifiers
> for use with this specification are described in the separate JSON
> Web Algorithms (JWA) specification and IANA registries defined by
> that specification. Related digital signature and Message
> Authentication Code (MAC) capabilities are described in the separate
> JSON Web Signature (JWS) specification.

Token Decryption is a 2-step process, between the producer and the recipient:

- **Key sharing**: both party agree on a way to share a Content-Encryption Key (CEK). This method is described in the
  "alg" header of the JWT.
- **Decryption**: both party agree on an algorithm used to decrypt the claims of the token. This algorithm takes the
  CEK as an input, and can either produce or decode claims. This algorithm is described in the "enc" header of the JWT.

## Key sharing

First, choose a Key Decoder to retrieve the Content-Encryption Key from the token / producer:

- [Direct Key Encryption](./direct.md)
- [Key Wrapping](./key_wrap.md)
- [Key Agreement](./key_agreement.md)
- [Key Agreement with Key Wrapping](./key_agreement_with_key_wrap.md)
- [Key Encryption (PBES2)](./key_encryption_pbes2.md)
- [Key Encryption (RSA)](./key_encryption_rsa.md)

## Decryption

Once you have a Key Decoder, and a Content-Encryption Key, you can decrypt your token.

::: tabs

@tab AES CBC

```go
package main

import (
	"github.com/a-novel-kit/jwt"
	"github.com/a-novel-kit/jwt/jwe"
)

func main() {
	// Create one using any of the methods above.
	var decoder jwe.CEKDecoder

	decrypter := jwe.NewAESCBCDecryption(
		&jwe.AESCBCDecryptionConfig{CEKDecoder: manager},
		jwe.A128CBCHS256,
	)

	recipient := jwt.NewRecipient(jwt.RecipientConfig{
		Plugins: []jwt.RecipientPlugin{decrypter},
	})
}
```

Available presets:

| Preset             | Target "enc"  |
| ------------------ | ------------- |
| `jwe.A128CBCHS256` | A128CBC-HS256 |
| `jwe.A192CBCHS384` | A192CBC-HS384 |
| `jwe.A256CBCHS512` | A256CBC-HS512 |

@tab AES GCM

```go
package main

import (
	"github.com/a-novel-kit/jwt"
	"github.com/a-novel-kit/jwt/jwe"
)

func main() {
	// Create one using any of the methods above.
	var decoder jwe.CEKDecoder

	decrypter := jwe.NewAESGCMDecryption(
		&jwe.AESGCMDecryptionConfig{CEKDecoder: manager},
		jwe.A128GCM,
	)

	recipient := jwt.NewRecipient(jwt.RecipientConfig{
		Plugins: []jwt.RecipientPlugin{decrypter},
	})
}
```

Available presets:

| Preset        | Target "enc"    |
| ------------- | --------------- |
| `jwe.A128GCM` | A128CBC-A128GCM |
| `jwe.A192GCM` | A192CBC-A192GCM |
| `jwe.A256GCM` | A256CBC-A256GCM |

:::
