package jwa

type Enc string

func (enc Enc) String() string {
	return string(enc)
}

// https://datatracker.ietf.org/doc/html/rfc7518#section-5.1
const (
	// A128CBC encryption algorithm.
	//
	// AES_128_CBC_HMAC_SHA_256 authenticated encryption algorithm.
	A128CBC Enc = "A128CBC-HS256"
	// A192CBC encryption algorithm.
	//
	// AES_192_CBC_HMAC_SHA_384 authenticated encryption algorithm.
	A192CBC Enc = "A192CBC-HS384"
	// A256CBC encryption algorithm.
	//
	// AES_256_CBC_HMAC_SHA_512 authenticated encryption algorithm.
	A256CBC Enc = "A256CBC-HS512"

	// A128GCM encryption algorithm.
	//
	// AES_128_GCM authenticated encryption algorithm.
	A128GCM Enc = "A128GCM"
	// A192GCM encryption algorithm.
	//
	// AES_192_GCM authenticated encryption algorithm.
	A192GCM Enc = "A192GCM"
	// A256GCM encryption algorithm.
	//
	// AES_256_GCM authenticated encryption algorithm.
	A256GCM Enc = "A256GCM"
)
