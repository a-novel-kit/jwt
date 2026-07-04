package serializers

import "errors"

// ErrUnsupportedCurve is returned by a decoder when the payload names a curve this library cannot handle.
var ErrUnsupportedCurve = errors.New("unsupported curve")
