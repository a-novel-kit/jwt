---
outline: deep
---

# Direct Key Encryption

Direct Key Encryption is the process of directly exchanging the CEK between the recipient and the producer.

::: warning
When using this method, both party are responsible for safely keeping the key, and sharing it through a secure
channel.
:::

```go
package main

import "github.com/a-novel-kit/jwt/jwe/jwek"

func main() {
	// The CEK is shared directly between the producer and the recipient.
	var cek []byte

	keyManager := jwek.NewDirectKeyManager(cek)
}
```

When using this method, the `ENC_KEY` part of the JWE is the empty string.
