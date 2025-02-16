---
title: Key Agreement with Key Wrapping
icon: material-symbols:encrypted-add-outline-rounded
category:
  - recipient
  - encryption
  - key sharing
---

# Key Agreement with Key Wrapping

Using the exact same principle as [Key Agreement](./key_agreement.md), Key Agreement with Key Wrapping
uses a dual private/public key pair to generate a shared secret. The only difference is the result of this
derivation will be used as the Key-Encryption Key (KEK) for a [Key Wrapping](./key_wrap.md) operation.

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

	keyDecoder := jwek.NewECDHKeyAgrKWDecoder(
		&jwek.ECDHKeyAgrKWDecoderConfig{RecipientKey: recipientPrivateKey},
		jwek.ECDHESA128KW,
	)
}
```

Available presets:

| Preset              | Target "alg"   |
| ------------------- | -------------- |
| `jwek.ECDHESA128KW` | ECDH-ES+A128KW |
| `jwek.ECDHESA192KW` | ECDH-ES+A192KW |
| `jwek.ECDHESA256KW` | ECDH-ES+A256KW |
