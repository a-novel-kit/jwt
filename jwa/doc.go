// Package jwa defines the JOSE data types shared across the jwt toolkit: the algorithm, key, header,
// and claim structures of the JSON Web Signature, Encryption, Key, and Token specifications (RFC
// 7515-7519, RFC 8037, RFC 9864, RFC 9964).
//
// The package holds only the wire types and their registered constant values. It carries no
// cryptographic logic, and the serialization and signing packages build on its types.
package jwa
