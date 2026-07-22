package internal

import (
	"crypto"
	"encoding/binary"
	"errors"
	"fmt"
)

// ErrDataTooLarge is returned when an input length exceeds the 32-bit field used to encode it in a
// length-prefixed KDF block.
var ErrDataTooLarge = errors.New("data is too large")

// Derive computes a key of keySize bytes from the ECDH shared secret z, following the ECDH-ES key
// agreement of RFC 7518. alg is the algorithm identifier bound into the derivation: the "enc" value
// for Direct Key Agreement, or the "alg" value when the derived key wraps the content key. apu and
// apv are the decoded PartyUInfo and PartyVInfo agreement parameters, either of which may be empty.
//
// They are []byte because the header carries them base64url-encoded. Passing the header field
// straight through derives a different key from every compliant implementation, and both ends being
// wrong together hides it.
func Derive(z []byte, alg string, keySize int, apu, apv []byte) ([]byte, error) {
	// AlgorithmID, PartyUInfo, and PartyVInfo make up the ConcatKDF OtherInfo, each carried as a
	// length-prefixed block.
	algID, err := prefixBlock([]byte(alg))
	if err != nil {
		return nil, fmt.Errorf("prefix algID: %w", err)
	}

	ptyUInfo, err := prefixBlock(apu)
	if err != nil {
		return nil, fmt.Errorf("prefix ptyUInfo: %w", err)
	}

	ptyVInfo, err := prefixBlock(apv)
	if err != nil {
		return nil, fmt.Errorf("prefix ptyVInfo: %w", err)
	}

	// SuppPubInfo carries the output key length in bits as a 32-bit big-endian integer.
	supPubInfo := make([]byte, 4)

	if keySize > 0xFFFFFFF {
		return nil, fmt.Errorf("%w: %d", ErrDataTooLarge, keySize)
	}

	binary.BigEndian.PutUint32(supPubInfo, uint32(keySize*8))

	// SuppPrivInfo is unused here and stays empty.
	var supPrivInfo []byte

	return ConcatKDF(crypto.SHA256, z, keySize, algID, ptyUInfo, ptyVInfo, supPubInfo, supPrivInfo), nil
}

// prefixBlock returns data prefixed with its length as a 32-bit big-endian integer, the
// Datalen || Data framing that ConcatKDF's OtherInfo fields require. It fails if data is longer than
// that length field can encode.
func prefixBlock(data []byte) ([]byte, error) {
	out := make([]byte, len(data)+4)

	if len(data) > 0xFFFFFFF {
		return nil, fmt.Errorf("%w: %d", ErrDataTooLarge, len(data))
	}

	binary.BigEndian.PutUint32(out, uint32(len(data)))
	copy(out[4:], data)

	return out, nil
}
