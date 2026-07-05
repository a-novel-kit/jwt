package jwp

import "github.com/a-novel-kit/jwt/v2"

// Compile-time checks for the higher-level helpers: the key embedder is a static producer plugin,
// and the claim checks satisfy the checker interfaces.
var (
	_ jwt.ProducerStaticPlugin = (*EmbedKey)(nil)

	_ ClaimsCheck = (*ClaimsCheckTarget)(nil)
	_ ClaimsCheck = (*ClaimsCheckTimestamp)(nil)

	_ RawClaimsCheck = (*RawClaimsChecker[any])(nil)
)
