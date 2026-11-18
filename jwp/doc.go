// Package jwp holds optional helpers built from the lower-level packages, for needs many token flows
// share, such as validating registered claims before decoding them. The lower-level packages never
// depend on it.
//
// Despite its name, it is unrelated to JSON Web Proof (JWP), the IETF JOSE drafts: this library
// does not implement them.
package jwp
