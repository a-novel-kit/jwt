---
title: Key Agreement
icon: material-symbols:handshake-outline-rounded
category:
  - recipient
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
	// Private key used by the recipient. The public
	// version of this key MUST have been shared to
	// the producer, ahead of the token creation.
	var recipientPrivateKey *ecdh.PrivateKey

	keyDecoder := jwek.NewECDHKeyAgrDecoder(
		&jwek.ECDHKeyAgrDecoderConfig{RecipientKey: recipientPrivateKey},
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
