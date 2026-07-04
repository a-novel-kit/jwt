package jwa

// KeyOp is a single operation a key may perform, as listed in the "key_ops" JWK
// parameter. The values match the KeyUsage names of the Web Cryptography API.
type KeyOp string

func (kop KeyOp) String() string {
	return string(kop)
}

const (
	// KeyOpSign computes a digital signature or MAC.
	KeyOpSign KeyOp = "sign"
	// KeyOpVerify verifies a digital signature or MAC.
	KeyOpVerify KeyOp = "verify"
	// KeyOpEncrypt encrypts content.
	KeyOpEncrypt KeyOp = "encrypt"
	// KeyOpDecrypt decrypts content, validating the decryption if applicable.
	KeyOpDecrypt KeyOp = "decrypt"
	// KeyOpWrapKey encrypts a key.
	KeyOpWrapKey KeyOp = "wrapKey"
	// KeyOpUnwrapKey decrypts a key, validating the decryption if applicable.
	KeyOpUnwrapKey KeyOp = "unwrapKey"
	// KeyOpDeriveKey derives a key.
	KeyOpDeriveKey KeyOp = "deriveKey"
	// KeyOpDeriveBits derives bits not to be used as a key.
	KeyOpDeriveBits KeyOp = "deriveBits"
)

// KeyOps is the set of operations a key is allowed to perform, serialized as
// the "key_ops" JWK parameter.
type KeyOps []KeyOp

func (kop KeyOps) Strings() []string {
	ret := make([]string, len(kop))
	for i, op := range kop {
		ret[i] = op.String()
	}

	return ret
}
