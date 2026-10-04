package testutils

// UndecodableSegment is a token segment that passes a recipient's compact-alphabet check yet is not
// valid base64url, since a lone character encodes no whole byte. Substituting it for one segment
// reaches that segment's decoder; a character outside the alphabet is refused before any decoding.
const UndecodableSegment = "A"
