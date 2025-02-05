---
title: Key Encryption (PBES2)
icon: material-symbols:password-rounded
category:
  - producer
  - encryption
  - key sharing
---

# Key Encryption (PBES2)

Key encryption uses a shared passkey to encrypt the CEK, very similar to key wrapping. Unlike Key Wrapping, it does
not depend on a fixed key size, and can use any random passphrase as a KEK.

::: warning

Key Encryption with PBES2 requires 2 parameters: an iterations count and a salt size. The minimum recommended values
are 1000 for iterations and 16 (128 bits) for salt size.

:::

```go
package main

import "github.com/a-novel-kit/jwt/jwe/jwek"

func main() {
	var cek []byte

	// Passphrase only known to the producer and the recipient.
	var passphrase string

	keyManager := jwek.NewPBES2KeyEncKWManager(
		&jwek.PBES2KeyEncKWManagerConfig{
			CEK: cek, Secret: passphrase,
			Iterations: 1000, SaltSize: 16,
		},
		jwek.PBES2A128KW,
	)
}
```

Available presets:

| Preset             | Target "alg"       |
|--------------------|--------------------|
| `jwek.PBES2A128KW` | PBES2-HS256+A128KW |
| `jwek.PBES2A192KW` | PBES2-HS384+A192KW |
| `jwek.PBES2A256KW` | PBES2-HS512+A256KW |
