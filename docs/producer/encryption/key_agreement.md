---
title: Key Agreement
icon: material-symbols:handshake-outline-rounded
category:
  - producer
  - encryption
  - key sharing
---

# Key Agreement

Key Agreement is, much like [Key Wrapping](./key_wrap.md), a method to pass the CEK in the token using a Key-Encryption
Key (KEK). Unlike Key Wrapping, which requires exchanging a symmetric KEK between the producer and the recipient, Key
Agreement uses a mathematical property of Elliptic Curves to generate a shared secret, which can be used as a KEK.

::: info How it works

Given `Derive` a method that computes a secret Z from a private key and a public key. The 2 equations:

```
Zprod = Derive(ProducerPrivateKey, RecipientPublicKey)
```

and

```
Zrec = Derive(RecipientPrivateKey, ProducerPublicKey)
```

Will both yield the same result, meaning:

```
Zprod = Zrec
```

Using this property, both party can exchange their (non-critical) public keys, and compute a secret only known to
themselves, without ever exposing private information.

:::

```go
package main

import (
	"crypto/ecdh"
	"github.com/a-novel-kit/jwt/jwe/jwek"
)

func main() {
	// Public key shared by the recipient, ahead of the operation.
	var recipientPublicKey *ecdh.PublicKey

	// Private key used by the producer.
	var producerPrivateKey *ecdh.PrivateKey

	keyManager := jwek.NewECDHKeyAgrManager(
		&jwek.ECDHKeyAgrManagerConfig{
			ProducerKey: producerPrivateKey,
			RecipientKey: recipientPublicKey,
			// Required to authenticate the data when decoding.
			ProducerInfo: "Bob",
			RecipientInfo: "Alice",
		},
		jwek.ECDHESA128CBC,
	)
}
```

Available presets:

| Preset               | Target "enc" |
|----------------------|--------------|
| `jwek.ECDHESA128CBC` | A128CBC      |
| `jwek.ECDHESA192CBC` | A192CBC      |
| `jwek.ECDHESA256CBC` | A256CBC      |
| `jwek.ECDHESA128GCM` | A128GCM      |
| `jwek.ECDHESA192GCM` | A192GCM      |
| `jwek.ECDHESA256GCM` | A256GCM      |

::: warning

Unlike most Key Managers, the ECDH Key Agreement is not agnostic to the "enc" algorithm used.

Using a preset that mismatch the "enc" algorithm used by the encrypter will result in an error.

:::
