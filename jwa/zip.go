package jwa

type Zip string

func (z Zip) String() string { return string(z) }

const (
	ZipDeflate Zip = "DEF"
)
