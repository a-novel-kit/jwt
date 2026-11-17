package jwek_test

import (
	"crypto/ecdh"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt/v2"
	"github.com/a-novel-kit/jwt/v2/jwa"
	"github.com/a-novel-kit/jwt/v2/jwe"
	"github.com/a-novel-kit/jwt/v2/jwe/jwek"
	"github.com/a-novel-kit/jwt/v2/jwk"
)

func TestECDHKeyAgrKWDecoder(t *testing.T) {
	t.Parallel()

	recipientKey, recipientPublicKey, err := jwk.GenerateECDHKey(jwk.ECDHESX25519)
	require.NoError(t, err)

	manager := jwek.NewECDHKeyAgrKWManager(&jwek.ECDHKeyAgrKWManagerConfig{
		RecipientKey:  recipientPublicKey.Key(),
		ProducerInfo:  "producer",
		RecipientInfo: "recipient",
	}, jwek.ECDHESA128KW)

	header, err := manager.SetHeader(t.Context(), &jwa.JWH{JWHCommon: jwa.JWHCommon{Enc: jwa.A256GCM}})
	require.NoError(t, err)

	cek, err := manager.ComputeCEK(t.Context(), header)
	require.NoError(t, err)

	encryptedKey, err := manager.EncryptCEK(t.Context(), header, cek)
	require.NoError(t, err)

	newDecoder := func(key *ecdh.PrivateKey) jwe.CEKDecoder {
		return jwek.NewECDHKeyAgrKWDecoder(&jwek.ECDHKeyAgrKWDecoderConfig{RecipientKey: key}, jwek.ECDHESA128KW)
	}

	// A mismatched apu or apv derives another key-wrapping key, which fails to unwrap the CEK.
	runAgreementFaults(t, newDecoder, recipientKey, header, encryptedKey, cek, jwt.ErrTokenRejected)

	t.Run("Error/MissingEncKey", func(t *testing.T) {
		t.Parallel()

		_, err := newDecoder(recipientKey.Key()).ComputeCEK(t.Context(), header, nil)
		require.ErrorIs(t, err, jwt.ErrUnsupportedTokenFormat)
	})
}
