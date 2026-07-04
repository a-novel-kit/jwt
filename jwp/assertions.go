package jwp

import "github.com/a-novel-kit/jwt"

// Compile-time checks for the higher-level helpers: the key embedder is a static producer plugin,
// and the claim checks satisfy the checker interfaces.
var (
	_ jwt.ProducerStaticPlugin = (*EmbedKey[any])(nil)

	_ ClaimsCheck = (*ClaimsCheckTarget)(nil)
	_ ClaimsCheck = (*ClaimsCheckTimestamp)(nil)

	_ RawClaimsCheck = (*RawClaimsChecker[any])(nil)
)
