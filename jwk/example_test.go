package jwk_test

import (
	"encoding/json"
	"fmt"

	"github.com/a-novel-kit/jwt/v2/jwa"
	"github.com/a-novel-kit/jwt/v2/jwk"
)

// ExampleGenerateECDSA generates an ES256 key pair, serializes the public half as a JSON Web Key,
// then consumes that JSON on the verifying side. Both halves share one key ID, so a verifier finds
// the public half under the ID the signer stamps on its tokens.
func ExampleGenerateECDSA() {
	privateKey, publicKey, err := jwk.GenerateECDSA(jwk.ES256)
	if err != nil {
		panic(err)
	}

	// The private half stays with the signer. The public half is what a JWK Set publishes.
	serialized, err := json.Marshal(publicKey)
	if err != nil {
		panic(err)
	}

	var published jwa.JWK

	err = json.Unmarshal(serialized, &published)
	if err != nil {
		panic(err)
	}

	consumedPrivate, consumedPublic, err := jwk.ConsumeECDSA(&published, jwk.ES256)
	if err != nil {
		panic(err)
	}

	fmt.Println(published.KTY, published.Use, published.KeyOps, published.Alg)
	fmt.Println(published.KID == privateKey.KID, consumedPrivate == nil)
	fmt.Println(consumedPublic.Key().Equal(&privateKey.Key().PublicKey))
	// Output:
	// EC sig [verify] ES256
	// true true
	// true
}
