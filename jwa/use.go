package jwa

// Use is the "use" parameter of a JWK. It marks whether the key is intended for
// signing or for encryption.
type Use string

func (u Use) String() string { return string(u) }

const (
	// UseSig means that the key is used for signing.
	UseSig Use = "sig"
	// UseEnc means that the key is used for encryption.
	UseEnc Use = "enc"
)
