# Contributing To JWT

The platform setup, local toolchain, and day-to-day workspace commands live in the
[developer onboarding guide](https://github.com/a-novel-kit/.github/blob/master/README.md). Read the
[README](./README.md) first for the library's public role and usage surface.

## What Belongs Here

`jwt` is a graduated `a-novel-kit` Go library. It is public API, not service-local glue, so changes need a stronger
reason than "one caller needs this today." Add behavior here when it belongs to the JOSE/JWT domain itself, serves more
than one consumer, and cannot be covered cleanly by the Go standard library or an existing dependency already in the
module.

Keep application policy out of the package. The library should expose primitives for producing, consuming, signing,
encrypting, validating, and working with JSON Web Keys; callers decide where keys are stored, which issuers are trusted,
which audiences are valid, and how tokens are transported.

## API Shape

The root package owns token orchestration. `Producer` builds the header and claims payload, then applies producer
plugins. `Recipient` decodes a token header, tries recipient plugins until one matches the token shape, and then
deserializes the claims.

Specialized packages own the standards-level pieces:

| Package    | Maintainer focus                                                                                               |
| ---------- | -------------------------------------------------------------------------------------------------------------- |
| `jwa`      | Keep JOSE and JWT structures faithful to the RFC fields, including custom JSON payload handling.               |
| `jwk`      | Keep key generation and consumption strict. JWK metadata checks are security boundaries, not convenience code. |
| `jws`      | Keep signing and verification plugins focused on authentication and integrity.                                 |
| `jwe`      | Keep content encryption/decryption separate from key-encryption mechanics.                                     |
| `jwe/jwek` | Keep key management algorithms interchangeable behind `jwe.CEKManager` and `jwe.CEKDecoder`.                   |
| `jwp`      | Keep higher-level helpers optional and built from the lower-level primitives.                                  |

Prefer adding a new plugin or preset over special-casing behavior inside `Producer` or `Recipient`. The orchestration
types should stay small and predictable.

## Documentation

This repo does not publish a separate Pages documentation site. The README is the external-user guide: global role,
installation, the first interaction path, and the package map. CONTRIBUTING is the maintainer guide: concepts,
rationale, and change boundaries.

Detailed symbol-level behavior belongs in Go doc comments and examples near the code. A README section should explain
why a package exists and when to use it; it should not duplicate every exported function that `pkg.go.dev` and
IntelliSense already show.

## Security Notes

Treat key metadata checks as part of the security model. Consumers in `jwk` intentionally reject keys that do not
declare compatible usage, operations, and algorithm values. Do not weaken those checks to make malformed fixtures pass;
fix the fixture or add an explicit compatibility path with tests that show why it is safe.

Do not log, trace, or return private keys, shared secrets, signed tokens, encrypted tokens, or password-derived
material. Error messages should identify the operation and condition without echoing credential material.

Avoid deprecated algorithms in new examples and tests. `RSA-OAEP` with SHA-1 remains available for compatibility, but
new code should prefer the SHA-256 variant where RSA-OAEP is required.

## Local Checks

Use the repository commands through pnpm and the `a-novel` CLI:

```bash
pnpm format
pnpm lint
a-novel test --type=go -y
```

Run `pnpm generate:go` only when a generated Go input changes. Keep generated artifacts in the same commit as the
source change that required them.

## Questions?

Open an issue in this repository when the question is specific to `jwt`. Use the platform onboarding guide for general
workspace, CLI, and release-process questions.
