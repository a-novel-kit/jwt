---
title: Key Encryption (PBES2)
icon: material-symbols:password-rounded
category:
  - recipient
  - encryption
  - key sharing
---

# Key Encryption (PBES2)

Key encryption uses a shared passkey to encrypt the CEK, very similar to key wrapping. Unlike Key Wrapping, it does
not depend on a fixed key size, and can use any random passphrase as a KEK.

```go
package main

import "github.com/a-novel-kit/jwt/jwe/jwek"

func main() {
	// Passphrase only known to the producer and the recipient.
	var passphrase string

	keyDecoder := jwek.NewPBES2KeyEncKWDecoder(
		&jwek.PBES2KeyEncKWDecoderConfig{Secret: passphrase},
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
