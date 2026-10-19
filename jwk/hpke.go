package jwk

import (
	"crypto/ecdh"

	"github.com/a-novel-kit/jwt/v2/jwa"
)

// An HPKE suite's KEM is Diffie-Hellman over the preset's curve, so HPKE keys are key-agreement
// keys. Generate and parse them with [GenerateECDHKey] and [ConsumeECDHKey].
//
// https://datatracker.ietf.org/doc/html/draft-ietf-jose-hpke-encrypt#section-9
var (
	// HPKE0 generates or matches a P-256 key for HPKE-0.
	HPKE0 = ECDHPreset{
		Alg:   jwa.HPKE0,
		Curve: ecdh.P256(),
	}
	// HPKE1 generates or matches a P-384 key for HPKE-1.
	HPKE1 = ECDHPreset{
		Alg:   jwa.HPKE1,
		Curve: ecdh.P384(),
	}
	// HPKE2 generates or matches a P-521 key for HPKE-2.
	HPKE2 = ECDHPreset{
		Alg:   jwa.HPKE2,
		Curve: ecdh.P521(),
	}
	// HPKE3 generates or matches an X25519 key for HPKE-3.
	HPKE3 = ECDHPreset{
		Alg:   jwa.HPKE3,
		Curve: ecdh.X25519(),
	}
	// HPKE4 generates or matches an X25519 key for HPKE-4.
	HPKE4 = ECDHPreset{
		Alg:   jwa.HPKE4,
		Curve: ecdh.X25519(),
	}
	// HPKE7 generates or matches a P-256 key for HPKE-7.
	HPKE7 = ECDHPreset{
		Alg:   jwa.HPKE7,
		Curve: ecdh.P256(),
	}

	// HPKE0KE generates or matches a P-256 key for HPKE-0-KE.
	HPKE0KE = ECDHPreset{
		Alg:   jwa.HPKE0KE,
		Curve: ecdh.P256(),
	}
	// HPKE1KE generates or matches a P-384 key for HPKE-1-KE.
	HPKE1KE = ECDHPreset{
		Alg:   jwa.HPKE1KE,
		Curve: ecdh.P384(),
	}
	// HPKE2KE generates or matches a P-521 key for HPKE-2-KE.
	HPKE2KE = ECDHPreset{
		Alg:   jwa.HPKE2KE,
		Curve: ecdh.P521(),
	}
	// HPKE3KE generates or matches an X25519 key for HPKE-3-KE.
	HPKE3KE = ECDHPreset{
		Alg:   jwa.HPKE3KE,
		Curve: ecdh.X25519(),
	}
	// HPKE7KE generates or matches a P-256 key for HPKE-7-KE.
	HPKE7KE = ECDHPreset{
		Alg:   jwa.HPKE7KE,
		Curve: ecdh.P256(),
	}
)
