package jwk

import (
	"crypto/ecdh"

	"github.com/a-novel-kit/jwt/v2/jwa"
)

// HPKE keys, one preset per algorithm. An HPKE suite's KEM is Diffie-Hellman over the preset's
// curve, so its keys are key-agreement keys: generate and parse them with [GenerateECDHKey] and
// [ConsumeECDHKey].
//
// https://datatracker.ietf.org/doc/html/draft-ietf-jose-hpke-encrypt#section-9
var (
	HPKE0 = ECDHPreset{
		Alg:   jwa.HPKE0,
		Curve: ecdh.P256(),
	}
	HPKE1 = ECDHPreset{
		Alg:   jwa.HPKE1,
		Curve: ecdh.P384(),
	}
	HPKE2 = ECDHPreset{
		Alg:   jwa.HPKE2,
		Curve: ecdh.P521(),
	}
	HPKE3 = ECDHPreset{
		Alg:   jwa.HPKE3,
		Curve: ecdh.X25519(),
	}
	HPKE4 = ECDHPreset{
		Alg:   jwa.HPKE4,
		Curve: ecdh.X25519(),
	}
	HPKE7 = ECDHPreset{
		Alg:   jwa.HPKE7,
		Curve: ecdh.P256(),
	}

	HPKE0KE = ECDHPreset{
		Alg:   jwa.HPKE0KE,
		Curve: ecdh.P256(),
	}
	HPKE1KE = ECDHPreset{
		Alg:   jwa.HPKE1KE,
		Curve: ecdh.P384(),
	}
	HPKE2KE = ECDHPreset{
		Alg:   jwa.HPKE2KE,
		Curve: ecdh.P521(),
	}
	HPKE3KE = ECDHPreset{
		Alg:   jwa.HPKE3KE,
		Curve: ecdh.X25519(),
	}
	HPKE7KE = ECDHPreset{
		Alg:   jwa.HPKE7KE,
		Curve: ecdh.P256(),
	}
)
