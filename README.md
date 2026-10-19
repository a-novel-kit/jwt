# JWT

A modular JWT, JWS, JWE, and JWK library for Go.

[![X (formerly Twitter) Follow](https://img.shields.io/twitter/follow/agorastoryverse)](https://twitter.com/agorastoryverse)
[![Discord](https://img.shields.io/discord/1315240114691248138?logo=discord)](https://discord.gg/rp4Qr8cA)

<hr />

![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/a-novel-kit/jwt)
![GitHub repo file or directory count](https://img.shields.io/github/directory-file-count/a-novel-kit/jwt)
![GitHub code size in bytes](https://img.shields.io/github/languages/code-size/a-novel-kit/jwt)
![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/a-novel-kit/jwt/main.yaml)
[![codecov](https://codecov.io/gh/a-novel-kit/jwt/graph/badge.svg)](https://codecov.io/gh/a-novel-kit/jwt)

![Coverage graph](https://codecov.io/gh/a-novel-kit/jwt/graphs/sunburst.svg)

## What this is

`github.com/a-novel-kit/jwt/v2` builds and reads JSON Web Tokens from composable parts. The root
package produces and consumes tokens. Plugins sign, verify, encrypt, or decrypt them, and claims
checks validate their content.

The library exposes the JOSE standards directly. Use it when an application needs control over token
headers, algorithms, key material, and the order in which plugins transform a token.

The application owns key storage and distribution. The `jwk` package generates, parses, validates,
and caches JSON Web Keys, while persisting private keys and publishing public key sets stay with the
caller.

Full reference: godoc on [pkg.go.dev](https://pkg.go.dev/github.com/a-novel-kit/jwt/v2).

## Installation

```bash
go get github.com/a-novel-kit/jwt/v2
```

A release that requires action from consumers comes with a
[migration guide](docs/migrations/README.md).

A producer issues tokens and a recipient consumes them. This example signs a token with HMAC, then
verifies it and validates its registered claims before decoding the payload.

```go
ctx := context.Background()

key, err := jwk.GenerateHMAC(jwk.HS256)
if err != nil {
	return err
}

target := jwt.TargetConfig{Issuer: "accounts", Audience: jwa.Audience{"api"}, Subject: "user-123"}

producer := jwt.NewProducer(jwt.ProducerConfig{
	Plugins: []jwt.ProducerPlugin{jws.NewHMACSigner(key.Key(), jws.HS256)},
})

claims, err := jwt.NewBasicClaims(map[string]any{"role": "admin"}, jwt.ClaimsProducerConfig{
	TargetConfig: target,
	TTL:          15 * time.Minute,
})
if err != nil {
	return err
}

token, err := producer.Issue(ctx, claims, nil)
if err != nil {
	return err
}

checker := jwp.NewClaimsChecker(&jwp.ClaimsCheckerConfig{
	Checks: []jwp.ClaimsCheck{
		jwp.NewClaimsCheckTarget(target),
		jwp.NewClaimsCheckTimestamp(30*time.Second, true),
	},
})

recipient := jwt.NewRecipient(jwt.RecipientConfig{
	Deserializer: checker.Unmarshal,
	Plugins:      []jwt.RecipientPlugin{jws.NewHMACVerifier(key.Key(), jws.HS256)},
})

var payload map[string]any
if err := recipient.Consume(ctx, token, &payload); err != nil {
	return err
}
```

## Sub-packages

| Package           | Purpose                                                                                         |
| ----------------- | ----------------------------------------------------------------------------------------------- |
| `jwt`             | Issues and consumes tokens, running the plugins that secure them.                               |
| `jwa`             | Holds the JOSE wire types: headers, registered claims, keys, and algorithm identifiers.         |
| `jwk`             | Generates and parses JSON Web Keys, and caches the key sets that sourced plugins draw from.     |
| `jwk/serializers` | Converts native Go keys to and from the key members of a JSON Web Key.                          |
| `jwk/generators`  | Produces raw symmetric key material.                                                            |
| `jws`             | Signs and verifies tokens with HMAC, ECDSA, Ed25519, ML-DSA, RSA, and RSA-PSS.                  |
| `jwe`             | Encrypts and decrypts tokens with AES-CBC-HMAC or AES-GCM content encryption, or with HPKE.     |
| `jwe/jwek`        | Delivers the content encryption key: direct keys, AES wrapping, ECDH-ES, RSA-OAEP, PBES2, HPKE. |
| `jwp`             | Advertises the signing key in the header, and validates registered claims before decoding.      |
| `testutils`       | Helps consumers test their token flows, for example with a key source serving fixed keys.       |

### Keys

`jwk.Key[T]` carries both the JSON Web Key and the native Go key. `Key()` returns the native key, and
`json.Marshal` turns the wrapper back into interoperable JWK JSON.

```go
privateKey, publicKey, err := jwk.GenerateECDSA(jwk.ES256)
if err != nil {
	return err
}

serializedPublicKey, err := json.Marshal(publicKey)
if err != nil {
	return err
}

ecdsaPrivateKey := privateKey.Key()
```

A Consume function accepts a key only when it declares the use, operations, and algorithm its
preset expects. The JWK `"alg"` of a content encryption key holds the `"enc"` value it serves.

### Plugins

Producer plugins run in order, after the static plugins. A static plugin only amends the header. A
transforming plugin sets its header fields, then transforms the serialized token. Signers and
encrypters each claim the `"alg"` header, so a producer takes one of them, and a second fails with
`jwt.ErrConflictingHeader`.

Recipient plugins also run in order. A plugin that does not recognize the token returns
`jwt.ErrMismatchRecipientPlugin`, and the recipient tries the next one. The first plugin that
succeeds supplies the claims payload.

A recipient consumes unsecured (`"alg":"none"`) tokens only when its plugins include
`jwt.NewDefaultRecipientPlugin()`, since RFC 7518 forbids accepting them by default. Keep them to
tests and trusted internal hops.

### Standards

The data structures follow the JOSE specifications:

| Standard | Scope                                                        |
| -------- | ------------------------------------------------------------ |
| RFC 7515 | JSON Web Signature (JWS)                                     |
| RFC 7516 | JSON Web Encryption (JWE)                                    |
| RFC 7517 | JSON Web Key (JWK)                                           |
| RFC 7518 | JSON Web Algorithms (JWA)                                    |
| RFC 7519 | JSON Web Token (JWT) registered data                         |
| RFC 8037 | Ed25519 signatures and X25519 key agreement (`OKP` keys)     |
| RFC 8725 | JWT Best Current Practices                                   |
| RFC 9864 | Fully-specified algorithms: `Ed25519` replaces `EdDSA`       |
| RFC 9964 | ML-DSA post-quantum signatures (`AKP` keys)                  |
| HPKE     | HPKE for JWE (draft-ietf-jose-hpke-encrypt, IANA-registered) |

Tokens use the compact serialization. The
[IANA JOSE registries](https://www.iana.org/assignments/jose/jose.xhtml) list every registered
algorithm and parameter.

## Contributing

New to the platform? Start with the [developer guide](https://a-novel-kit.github.io/stack/).
For repository-specific conventions, read [CONTRIBUTING.md](./CONTRIBUTING.md).
