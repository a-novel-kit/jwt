package internal_test

import (
	"crypto/aes"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt/jwe/internal"
)

func TestAesKeyWrap(t *testing.T) {
	t.Parallel()

	// Test vectors from: http://csrc.nist.gov/groups/ST/toolkit/documents/kms/key-wrap.pdf
	kek0, _ := hex.DecodeString("000102030405060708090A0B0C0D0E0F")
	cek0, _ := hex.DecodeString("00112233445566778899AABBCCDDEEFF")

	expected0, _ := hex.DecodeString("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5")

	kek1, _ := hex.DecodeString("000102030405060708090A0B0C0D0E0F1011121314151617")
	cek1, _ := hex.DecodeString("00112233445566778899AABBCCDDEEFF")

	expected1, _ := hex.DecodeString("96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D")

	kek2, _ := hex.DecodeString("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
	cek2, _ := hex.DecodeString("00112233445566778899AABBCCDDEEFF0001020304050607")

	expected2, _ := hex.DecodeString("A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1")

	block0, _ := aes.NewCipher(kek0)
	block1, _ := aes.NewCipher(kek1)
	block2, _ := aes.NewCipher(kek2)

	out0, _ := internal.KeyWrap(block0, cek0)
	out1, _ := internal.KeyWrap(block1, cek1)
	out2, _ := internal.KeyWrap(block2, cek2)

	require.Equal(t, expected0, out0)
	require.Equal(t, expected1, out1)
	require.Equal(t, expected2, out2)

	unwrap0, _ := internal.KeyUnwrap(block0, out0)
	unwrap1, _ := internal.KeyUnwrap(block1, out1)
	unwrap2, _ := internal.KeyUnwrap(block2, out2)

	require.Equal(t, cek0, unwrap0)
	require.Equal(t, cek1, unwrap1)
	require.Equal(t, cek2, unwrap2)
}

func TestAesKeyWrapInvalid(t *testing.T) {
	t.Parallel()

	kek, _ := hex.DecodeString("000102030405060708090A0B0C0D0E0F")

	// Invalid unwrap input (bit flipped)
	input0, _ := hex.DecodeString("1EA68C1A8112B447AEF34BD8FB5A7B828D3E862371D2CFE5")

	block, _ := aes.NewCipher(kek)

	_, err := internal.KeyUnwrap(block, input0)
	require.Error(t, err, "key unwrap failed to detect invalid input")

	// Invalid unwrap input (truncated)
	input1, _ := hex.DecodeString("1EA68C1A8112B447AEF34BD8FB5A7B828D3E862371D2CF")

	_, err = internal.KeyUnwrap(block, input1)
	require.Error(t, err, "key unwrap failed to detect truncated input")

	// Invalid wrap input (not multiple of 8)
	input2, _ := hex.DecodeString("0123456789ABCD")

	_, err = internal.KeyWrap(block, input2)
	require.Error(t, err, "key wrap accepted invalid input")
}
