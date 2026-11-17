package internal_test

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt/v2/jwe/internal"
)

// keyWrapVectors are the worked examples of RFC 3394 §4, one per KEK and key data size.
//
// https://datatracker.ietf.org/doc/html/rfc3394#section-4
var keyWrapVectors = []struct {
	name string

	kek        string
	keyData    string
	ciphertext string
}{
	{
		name:       "RFC3394-4.1",
		kek:        "000102030405060708090A0B0C0D0E0F",
		keyData:    "00112233445566778899AABBCCDDEEFF",
		ciphertext: "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5",
	},
	{
		name:       "RFC3394-4.2",
		kek:        "000102030405060708090A0B0C0D0E0F1011121314151617",
		keyData:    "00112233445566778899AABBCCDDEEFF",
		ciphertext: "96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D",
	},
	{
		name:       "RFC3394-4.3",
		kek:        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
		keyData:    "00112233445566778899AABBCCDDEEFF",
		ciphertext: "64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7",
	},
	{
		name:       "RFC3394-4.4",
		kek:        "000102030405060708090A0B0C0D0E0F1011121314151617",
		keyData:    "00112233445566778899AABBCCDDEEFF0001020304050607",
		ciphertext: "031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2",
	},
	{
		name:       "RFC3394-4.5",
		kek:        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
		keyData:    "00112233445566778899AABBCCDDEEFF0001020304050607",
		ciphertext: "A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1",
	},
	{
		name:       "RFC3394-4.6",
		kek:        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
		keyData:    "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F",
		ciphertext: "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21",
	},
}

// The KEK of RFC 3394 §4.1, for the error cases.
const keyWrapKEK = "000102030405060708090A0B0C0D0E0F"

func TestKeyWrap(t *testing.T) {
	t.Parallel()

	for _, vector := range keyWrapVectors {
		t.Run("Success/"+vector.name, func(t *testing.T) {
			t.Parallel()

			out, err := internal.KeyWrap(mustDecodeHex(t, vector.kek), mustDecodeHex(t, vector.keyData))
			require.NoError(t, err)
			require.Equal(t, mustDecodeHex(t, vector.ciphertext), out)
		})
	}

	testCases := []struct {
		name string

		kek     string
		keyData string
	}{
		{
			name:    "Error/PartialBlock",
			kek:     keyWrapKEK,
			keyData: "0123456789ABCD",
		},
		{
			// RFC 3394 §2: the key data holds at least two 64-bit blocks.
			name:    "Error/OneBlock",
			kek:     keyWrapKEK,
			keyData: "0011223344556677",
		},
		{
			// AES takes a 16, 24 or 32-byte key.
			name:    "Error/ShortKEK",
			kek:     keyWrapKEK[:30],
			keyData: "00112233445566778899AABBCCDDEEFF",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			_, err := internal.KeyWrap(mustDecodeHex(t, testCase.kek), mustDecodeHex(t, testCase.keyData))
			require.Error(t, err)
		})
	}
}

func TestKeyUnwrap(t *testing.T) {
	t.Parallel()

	for _, vector := range keyWrapVectors {
		t.Run("Success/"+vector.name, func(t *testing.T) {
			t.Parallel()

			out, err := internal.KeyUnwrap(mustDecodeHex(t, vector.kek), mustDecodeHex(t, vector.ciphertext))
			require.NoError(t, err)
			require.Equal(t, mustDecodeHex(t, vector.keyData), out)
		})
	}

	testCases := []struct {
		name string

		kek        string
		ciphertext string
	}{
		{
			// The ciphertext of §4.1 with flipped bits fails the integrity check.
			name:       "Error/BitFlipped",
			kek:        keyWrapKEK,
			ciphertext: "1EA68C1A8112B447AEF34BD8FB5A7B828D3E862371D2CFE5",
		},
		{
			name:       "Error/Truncated",
			kek:        keyWrapKEK,
			ciphertext: "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CF",
		},
		{
			name: "Error/Empty",
			kek:  keyWrapKEK,
		},
		{
			name:       "Error/IntegrityCheckOnly",
			kek:        keyWrapKEK,
			ciphertext: "A6A6A6A6A6A6A6A6",
		},
		{
			// RFC 3394 §2: the wrapped key holds the integrity check value and at least two more blocks.
			name:       "Error/OneBlock",
			kek:        keyWrapKEK,
			ciphertext: "A6A6A6A6A6A6A6A60011223344556677",
		},
		{
			name:       "Error/ShortKEK",
			kek:        keyWrapKEK[:30],
			ciphertext: "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			_, err := internal.KeyUnwrap(mustDecodeHex(t, testCase.kek), mustDecodeHex(t, testCase.ciphertext))
			require.Error(t, err)
		})
	}
}

// mustDecodeHex decodes a hexadecimal test vector.
func mustDecodeHex(t *testing.T, value string) []byte {
	t.Helper()

	decoded, err := hex.DecodeString(value)
	if err != nil {
		panic(err)
	}

	return decoded
}
