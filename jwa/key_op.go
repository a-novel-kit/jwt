package jwa

// KeyOp is used to determine the operations that can be performed with a key in a JWA protocol.
type KeyOp string

func (kop KeyOp) String() string {
	return string(kop)
}

const (
	// KeyOpSign compute digital signature or MAC.
	KeyOpSign KeyOp = "sign"
	// KeyOpVerify verify digital signature or MAC.
	KeyOpVerify KeyOp = "verify"
	// KeyOpEncrypt encrypt content.
	KeyOpEncrypt KeyOp = "encrypt"
	// KeyOpDecrypt decrypt content and validate decryption, if applicable.
	KeyOpDecrypt KeyOp = "decrypt"
	// KeyOpWrapKey encrypt key.
	KeyOpWrapKey KeyOp = "wrapKey"
	// KeyOpUnwrapKey decrypt key and validate decryption, if applicable.
	KeyOpUnwrapKey KeyOp = "unwrapKey"
	// KeyOpDeriveKey derive key.
	KeyOpDeriveKey KeyOp = "deriveKey"
	// KeyOpDeriveBits derive bits not to be used as a key.
	KeyOpDeriveBits KeyOp = "deriveBits"
)

type KeyOps []KeyOp

func (kop KeyOps) Strings() []string {
	ret := make([]string, len(kop))
	for i, op := range kop {
		ret[i] = op.String()
	}

	return ret
}
