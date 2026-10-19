# Contributing to JWT

This document covers what is specific to `jwt`. Platform setup and day-to-day commands live in the
[developer guide](https://a-novel-kit.github.io/stack/), and the library taxonomy in the
[libraries, tooling & platform concepts](https://github.com/a-novel-kit/.github/blob/master/CONTRIBUTING.md).
Read the [README](./README.md) first for the library's role and usage.

## What belongs here

`jwt` is a graduated `a-novel-kit` library, so every exported symbol is public API. A change belongs
here when it serves the JOSE/JWT domain itself, has more than one consumer, and no standard library
package or existing dependency covers it cleanly.

The library exposes primitives for producing, consuming, signing, encrypting, validating, and
handling JSON Web Keys. Callers keep the policy: where keys are stored, which issuers to trust,
which audiences are valid, and how tokens travel.

## How the packages divide the work

The root package orchestrates a token, as the README's [plugin section](./README.md#plugins)
describes. Add behavior as a new plugin or preset, so `Producer` and `Recipient` stay small and
predictable. The specialized packages each own one part of the standards:

| Package    | Maintainer focus                                                                                 |
| ---------- | ------------------------------------------------------------------------------------------------ |
| `jwa`      | Keep JOSE and JWT structures faithful to the RFC fields, including custom JSON payload handling. |
| `jwk`      | Keep key generation and consumption strict. JWK metadata checks are a security boundary.         |
| `jws`      | Keep signing and verification plugins focused on authentication and integrity.                   |
| `jwe`      | Keep content encryption and decryption apart from key management.                                |
| `jwe/jwek` | Keep key management algorithms interchangeable behind `jwe.CEKManager` and `jwe.CEKDecoder`.     |
| `jwp`      | Keep higher-level helpers optional and built from the lower-level primitives.                    |

## Documentation

The README guides users, and this file guides maintainers. Symbol-level behavior belongs in Go doc
comments and examples beside the code, which pkg.go.dev and editors show. The migration guides in
[`docs/migrations`](docs/migrations/README.md) record the action each release requires from
consumers.

## Security

Key metadata checks are part of the security model. The `jwk` Consume functions reject a key that
does not declare compatible use, operations, and algorithm. Fix a malformed fixture instead of weakening those
checks, or add an explicit compatibility path with tests that show why it is safe.

Never log, trace, or return private keys, shared secrets, signed or encrypted tokens, or
password-derived material. An error names the operation and the condition, without the credential.

Keep deprecated algorithms out of new examples and tests. `RSA-OAEP` with SHA-1 stays available for
compatibility, and new code uses the SHA-256 variant where it needs RSA-OAEP.

## Local checks

Run these checks before pushing. CI runs them too, along with its security scans.

```bash
pnpm lint
a-novel test --type=go -y
bash .github/scripts/lint-hash-registration.sh .
```

`pnpm format` fixes what the linters can. The last command checks that every package naming a `crypto.Hash` imports the package that registers it, a gap the
test suite cannot observe.

## Questions?

[Open an issue](https://github.com/a-novel-kit/jwt/issues) when the question is specific to `jwt`.
The [developer guide](https://a-novel-kit.github.io/stack/) answers workspace, CLI, and release
questions.
