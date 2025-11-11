package jwa

// Use is used to determine the purpose of a key in a JWA protocol.
type Use string

func (u Use) String() string { return string(u) }

const (
	// UseSig means that the key is used for signing.
	UseSig Use = "sig"
	// UseEnc means that the key is used for encryption.
	UseEnc Use = "enc"
)
