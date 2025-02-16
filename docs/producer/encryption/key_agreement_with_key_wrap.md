---
title: Key Agreement with Key Wrapping
icon: material-symbols:encrypted-add-outline-rounded
category:
  - producer
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
	// You need to generate a CEK. As in key wrapping mode,
	// you don't need to forward it to the recipient
	// beforehand. The wrapped CEK will be inserted in
    // the token directly, as the ENC_KEY.
	var cek []byte

	// Public key shared by the recipient, ahead of the operation.
	var recipientPublicKey *ecdh.PublicKey

	// Private key used by the producer.
	var producerPrivateKey *ecdh.PrivateKey

	keyManager := jwek.NewECDHKeyAgrKWManager(
		&jwek.ECDHKeyAgrKWManagerConfig{
			CEK: cek,
			ProducerKey: producerPrivateKey,
			RecipientKey: recipientPublicKey,
			// Required to authenticate the data when decoding.
			ProducerInfo: "Bob",
			RecipientInfo: "Alice",
		},
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
