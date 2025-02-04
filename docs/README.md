---
title: Home
icon: material-symbols:home-outline-rounded
---

# JWT - A modular JSON Web Token library for Go.

Per the [specification](https://datatracker.ietf.org/doc/html/rfc7519):

> JSON Web Token (JWT) is a compact, URL-safe means of representing
> claims to be transferred between two parties. The claims in a JWT
> are encoded as a JSON object that is used as the payload of a JSON
> Web Signature (JWS) structure or as the plaintext of a JSON Web
> Encryption (JWE) structure, enabling the claims to be digitally
> signed or integrity protected with a Message Authentication Code
> (MAC) and/or encrypted.

This library was built in frustration of existing solutions, which felt complicated to setup / unintuitive to use.
Some goal highlights:

- **Modularity**: JWT is a permissive standard. The library uses a plugin-based approach, which allows users to
  define their own extensions.
- **Incremental complexity**: Simple tasks can be done with simple code, while complex problems can be solved by
  writing custom plugins, tailored for the task.
- **Low dependencies**: Golang offers an amazing set of cryptographic tools, which made this library possible with
  bare cryptographic knowledge and low reliance on external entities.

As everything, those choices came with tradeoffs:

- As this library focuses on the compact base64 representation, the full JSON representation is not supported yet.
  This means that features, such as multiple signatures, are not supported.
- Some newer algorithms, especially those not yet integrated in the Go crypto framework, might temporarily lack.
- The default plugins follow the RFC specifications very strictly, some lose interpretations might not work out
  of the box.

::: details Source specifications
JSON Web Token <a target="_blank" href="https://datatracker.ietf.org/doc/html/rfc7519">specification</a> \
JSON Web Algorithms <a target="_blank" href="https://datatracker.ietf.org/doc/html/rfc7518">specification</a> \
JSON Web Signature <a target="_blank" href="https://datatracker.ietf.org/doc/html/rfc7515">specification</a> \
JSON Web Encryption <a target="_blank" href="https://datatracker.ietf.org/doc/html/rfc7516">specification</a> \
JSON Web Keys <a target="_blank" href="https://datatracker.ietf.org/doc/html/rfc7517">specification</a>
:::
