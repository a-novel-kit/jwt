package jwek

import "github.com/a-novel-kit/jwt/v2/jwe"

// Compile-time checks that every key manager and decoder satisfies the jwe.CEKManager /
// jwe.CEKDecoder contract, so a drifting method signature fails the build.
var (
	_ jwe.CEKManager = (*AESGCMKWManager)(nil)
	_ jwe.CEKManager = (*RSAOAEPKeyEncManager)(nil)
	_ jwe.CEKManager = (*DirectKeyManager)(nil)
	_ jwe.CEKManager = (*ECDHKeyAgrManager)(nil)
	_ jwe.CEKManager = (*ECDHKeyAgrKWManager)(nil)
	_ jwe.CEKManager = (*PBES2KeyEncKWManager)(nil)
	_ jwe.CEKManager = (*AESKWManager)(nil)

	_ jwe.CEKDecoder = (*AESGCMKWDecoder)(nil)
	_ jwe.CEKDecoder = (*RSAOAEPKeyEncDecoder)(nil)
	_ jwe.CEKDecoder = (*DirectKeyDecoder)(nil)
	_ jwe.CEKDecoder = (*ECDHKeyAgrDecoder)(nil)
	_ jwe.CEKDecoder = (*ECDHKeyAgrKWDecoder)(nil)
	_ jwe.CEKDecoder = (*PBES2KeyEncKWDecoder)(nil)
	_ jwe.CEKDecoder = (*AESKWDecoder)(nil)
)
