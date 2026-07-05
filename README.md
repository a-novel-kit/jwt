# JWT

A modular JWT, JWS, JWE, and JWK library for Go.

[![X (formerly Twitter) Follow](https://img.shields.io/twitter/follow/agorastoryverse)](https://twitter.com/agorastoryverse)
[![Discord](https://img.shields.io/discord/1315240114691248138?logo=discord)](https://discord.gg/rp4Qr8cA)

<hr />

![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/a-novel-kit/jwt)
![GitHub repo file or directory count](https://img.shields.io/github/directory-file-count/a-novel-kit/jwt)
![GitHub code size in bytes](https://img.shields.io/github/languages/code-size/a-novel-kit/jwt)
![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/a-novel-kit/jwt/main.yaml)
[![Go Report Card](https://goreportcard.com/badge/github.com/a-novel-kit/jwt/v2)](https://goreportcard.com/report/github.com/a-novel-kit/jwt/v2)
[![codecov](https://codecov.io/gh/a-novel-kit/jwt/graph/badge.svg)](https://codecov.io/gh/a-novel-kit/jwt)

![Coverage graph](https://codecov.io/gh/a-novel-kit/jwt/graphs/sunburst.svg)

## What this is

`github.com/a-novel-kit/jwt/v2` provides composable building blocks for JSON Web Tokens in Go. The root package produces
and consumes token payloads; plugins add signing, verification, encryption, decryption, key headers, and claims
validation.

The library follows the JOSE family of standards rather than hiding them behind a single opinionated client. Use it
when an application needs direct control over token headers, algorithms, key material, and the order of token
transformations.

Key storage and distribution are deliberately out of scope. The `jwk` package can generate, parse, validate, and cache
JSON Web Keys, but the system that persists private keys or publishes public key sets remains the caller's
responsibility.

## Installation

```bash
go get github.com/a-novel-kit/jwt/v2
```

Upgrading across a major version? See the [migration guides](docs/migrations/README.md) — start
with [Upgrading to v2.0.0](docs/migrations/v2.0.0.md).

The root `jwt.Producer` and `jwt.Recipient` types handle the token lifecycle. With no plugins, they produce and consume
raw JWT payloads with the `"none"` algorithm; this is useful for tests and trusted internal hops, but production tokens
normally add JWS or JWE plugins.

```go
ctx := context.Background()

producer := jwt.NewProducer(jwt.ProducerConfig{})
token, err := producer.Issue(ctx, map[string]any{"sub": "user-123"}, nil)
if err != nil {
	return err
}

recipient := jwt.NewRecipient(jwt.RecipientConfig{})

var claims map[string]any
if err := recipient.Consume(ctx, token, &claims); err != nil {
	return err
}
```

Signing and verification are added through producer and recipient plugins. This HMAC example uses caller-provided key
material; the `jwk` package can generate and validate keys when the application needs JSON Web Key material.

```go
var secretKey []byte

producer := jwt.NewProducer(jwt.ProducerConfig{
	Plugins: []jwt.ProducerPlugin{
		jws.NewHMACSigner(secretKey, jws.HS256),
	},
})

token, err := producer.Issue(ctx, map[string]any{"sub": "user-123"}, nil)
if err != nil {
	return err
}

recipient := jwt.NewRecipient(jwt.RecipientConfig{
	Plugins: []jwt.RecipientPlugin{
		jws.NewHMACVerifier(secretKey, jws.HS256),
	},
})

var signedClaims map[string]any
if err := recipient.Consume(ctx, token, &signedClaims); err != nil {
	return err
}
```

For registered JWT claims, wrap the application payload with `jwt.NewBasicClaims` and validate it on the recipient side
with the `jwp` claims checker.

```go
claims, err := jwt.NewBasicClaims(map[string]any{"role": "admin"}, jwt.ClaimsProducerConfig{
	TargetConfig: jwt.TargetConfig{
		Issuer:   "accounts",
		Audience: "api",
		Subject:  "user-123",
	},
	TTL: 15 * time.Minute,
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
		jwp.NewClaimsCheckTarget(jwt.TargetConfig{
			Issuer:   "accounts",
			Audience: "api",
			Subject:  "user-123",
		}),
		jwp.NewClaimsCheckTimestamp(30*time.Second, true),
	},
})

recipient := jwt.NewRecipient(jwt.RecipientConfig{
	Deserializer: checker.Unmarshal,
	Plugins:      []jwt.RecipientPlugin{jws.NewHMACVerifier(secretKey, jws.HS256)},
})
```

## Sub-packages

| Package    | Purpose                                                                                                      |
| ---------- | ------------------------------------------------------------------------------------------------------------ |
| `jwt`      | Token producers, recipients, claim helpers, header helpers, and token decoders.                              |
| `jwa`      | Typed JOSE headers, registered JWT claims, algorithms, key metadata, and JSON merge behavior.                |
| `jwk`      | JWK generation, strict JWK consumption, typed key wrappers, and cached key sources.                          |
| `jws`      | JWS producer and recipient plugins for HMAC, ECDSA, Ed25519, RSA, RSA-PSS, and legacy `"none"` verification. |
| `jwe`      | JWE producer and recipient plugins for AES-CBC-HMAC and AES-GCM content encryption.                          |
| `jwe/jwek` | Content-encryption-key managers and decoders for direct keys, AES wrapping, ECDH, RSA-OAEP, and PBES2.       |
| `jwp`      | Higher-level producer/recipient helpers for embedding key references and validating registered claims.       |

### Keys

`jwk.Key[T]` carries both the serialized JSON Web Key and the concrete Go key. Calling `Key()` returns the usable Go
value, while `encoding/json` can marshal the same wrapper back to interoperable JWK JSON.

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

JWK consumers are intentionally strict: a key must declare compatible usage, operations, and algorithm metadata before
the parser accepts it. For encryption keys, the JWK `"alg"` value must match the JWT `"enc"` value the key is intended
to protect.

### Producer and Recipient Plugins

Producer plugins run in order. Static plugins modify only the header; transforming plugins update the header and then
transform the serialized token. Most applications should use one transforming plugin, because JWS and JWE change token
shape in different ways and often compete for the same JOSE header fields.

Recipient plugins also run in order. A plugin that does not recognize the token returns `jwt.ErrMismatchRecipientPlugin`
so the recipient can try the next plugin. The first plugin that succeeds supplies the raw claims payload for
deserialization.

### Standards

The core data structures follow the JOSE specifications:

| Standard | Scope                                |
| -------- | ------------------------------------ |
| RFC 7515 | JSON Web Signature (JWS)             |
| RFC 7516 | JSON Web Encryption (JWE)            |
| RFC 7517 | JSON Web Key (JWK)                   |
| RFC 7518 | JSON Web Algorithms (JWA)            |
| RFC 7519 | JSON Web Token (JWT) registered data |

## Contributing

New to the platform? Start with the [developer onboarding guide](https://github.com/a-novel-kit/.github/blob/master/README.md).
For repository-specific conventions, read [CONTRIBUTING.md](./CONTRIBUTING.md).
