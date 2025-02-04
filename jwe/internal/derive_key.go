package internal

import (
	"crypto"
	"encoding/binary"
	"errors"
	"fmt"
)

var ErrDataTooLarge = errors.New("data is too large")

// Derive a key from a shared secret.
//
// Alg is the algorithm ID.  In the Direct Key Agreement case, Data is set to the octets of the ASCII representation
// of the "enc" Header Parameter value. In the Key Agreement with Key Wrapping case, Data is set to the octets of the
// ASCII representation of the "alg" (algorithm) Header Parameter value.
//
// Key size is set to the number of bits in the desired output key. For "ECDH-ES", this is length of the key used by
// the "enc" algorithm. For "ECDH-ES+A128KW", "ECDH-ES+A192KW", and "ECDH-ES+A256KW", this is 128, 192, and 256,
// respectively.
//
// Apu is the Agreement PartyUInfo value. If an "apu" (agreement PartyUInfo) Header Parameter is present, Data is set
// to the result of base64url decoding the "apu" value and Datalen is set to the number of octets in Data. Otherwise,
// Datalen is set to 0 and Data is set to the empty octet sequence.
//
// Apv is the Agreement PartyVInfo value. If an "apv" (agreement PartyVInfo) Header Parameter is present, Data is set
// to the result of base64url decoding the "apv" value and Datalen is set to the number of octets in Data. Otherwise,
// Datalen is set to 0 and Data is set to the empty octet sequence.
func Derive(z []byte, alg string, keySize int, apu, apv string) ([]byte, error) {
	// The AlgorithmID value is of the form Datalen || Data, where Data
	// is a variable-length string of zero or more octets, and Datalen is
	// a fixed-length, big-endian 32-bit counter that indicates the
	// length (in octets) of Data.
	algID, err := prefixBlock([]byte(alg))
	if err != nil {
		return nil, fmt.Errorf("prefix algID: %w", err)
	}

	// The PartyUInfo value is of the form Datalen || Data, where Data is
	// a variable-length string of zero or more octets, and Datalen is a
	// fixed-length, big-endian 32-bit counter that indicates the length
	// (in octets) of Data.
	ptyUInfo, err := prefixBlock([]byte(apu))
	if err != nil {
		return nil, fmt.Errorf("prefix ptyUInfo: %w", err)
	}

	// The PartyVInfo value is of the form Datalen || Data, where Data is
	// a variable-length string of zero or more octets, and Datalen is a
	// fixed-length, big-endian 32-bit counter that indicates the length
	// (in octets) of Data.
	ptyVInfo, err := prefixBlock([]byte(apv))
	if err != nil {
		return nil, fmt.Errorf("prefix ptyVInfo: %w", err)
	}

	// This is set to the keydatalen represented as a 32-bit big-endian integer.
	supPubInfo := make([]byte, 4)
	if keySize > 0xFFFFFFF {
		return nil, fmt.Errorf("%w: %d", ErrDataTooLarge, keySize)
	}

	binary.BigEndian.PutUint32(supPubInfo, uint32(keySize*8))

	// This is set to the empty octet sequence.
	var supPrivInfo []byte

	// Derive the shared key.
	return ConcatKDF(crypto.SHA256, z, keySize, algID, ptyUInfo, ptyVInfo, supPubInfo, supPrivInfo), nil
}

// Prefix the input data with a 32-bit big-endian length.
func prefixBlock(data []byte) ([]byte, error) {
	out := make([]byte, len(data)+4)
	if len(data) > 0xFFFFFFF {
		return nil, fmt.Errorf("%w: %d", ErrDataTooLarge, len(data))
	}

	binary.BigEndian.PutUint32(out, uint32(len(data)))
	copy(out[4:], data)

	return out, nil
}
