package jwe_test

import (
	"context"
	"fmt"

	"github.com/a-novel-kit/jwt/v2"
	"github.com/a-novel-kit/jwt/v2/jwe"
	"github.com/a-novel-kit/jwt/v2/jwe/jwek"
	"github.com/a-novel-kit/jwt/v2/jwk"
)

// ExampleNewAESGCMEncryption encrypts a token to a recipient's X25519 key, then decrypts it with
// the private half. ECDH-ES derives a fresh content encryption key per token from an ephemeral key
// the token header carries, and AES-GCM encrypts the payload under it.
func ExampleNewAESGCMEncryption() {
	ctx := context.Background()

	privateKey, publicKey, err := jwk.GenerateECDHKey(jwk.ECDHESX25519)
	if err != nil {
		panic(err)
	}

	producer := jwt.NewProducer(jwt.ProducerConfig{
		Plugins: []jwt.ProducerPlugin{
			jwe.NewAESGCMEncryption(&jwe.AESGCMEncryptionConfig{
				CEKManager: jwek.NewECDHKeyAgrManager(
					&jwek.ECDHKeyAgrManagerConfig{RecipientKey: publicKey.Key()}, jwek.ECDHESA256GCM,
				),
			}, jwe.A256GCM),
		},
	})

	token, err := producer.Issue(ctx, map[string]any{"secret": "launch code"}, nil)
	if err != nil {
		panic(err)
	}

	recipient := jwt.NewRecipient(jwt.RecipientConfig{
		Plugins: []jwt.RecipientPlugin{
			jwe.NewAESGCMDecryption(&jwe.AESGCMDecryptionConfig{
				CEKDecoder: jwek.NewECDHKeyAgrDecoder(
					&jwek.ECDHKeyAgrDecoderConfig{RecipientKey: privateKey.Key()}, jwek.ECDHESA256GCM,
				),
			}, jwe.A256GCM),
		},
	})

	var claims map[string]any

	err = recipient.Consume(ctx, token, &claims)
	if err != nil {
		panic(err)
	}

	fmt.Println(claims["secret"])
	// Output: launch code
}
