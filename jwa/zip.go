package jwa

// Zip identifies the compression algorithm applied to a JWE plaintext before
// encryption, carried in the "zip" header parameter.
type Zip string

// String returns the parameter value as it appears in the JWE header.
func (z Zip) String() string { return string(z) }

const (
	// ZipDeflate selects DEFLATE compression, the "DEF" value registered by RFC 7516.
	ZipDeflate Zip = "DEF"
)
