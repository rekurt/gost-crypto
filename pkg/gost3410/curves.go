// Package gost3410 implements GOST R 34.10-2012 digital signatures
// using OpenSSL gost-engine.
package gost3410

import (
	"errors"
	"fmt"

	"github.com/rekurt/gost-crypto/internal/openssl"
)

// Curve identifies one of the eight TC26 elliptic-curve parameter sets
// defined in GOST R 34.10-2012.
type Curve int

const (
	CurveTC26_256_A Curve = iota // id-tc26-gost-3410-2012-256-paramSetA
	CurveTC26_256_B              // id-tc26-gost-3410-2012-256-paramSetB (CryptoPro-A)
	CurveTC26_256_C              // id-tc26-gost-3410-2012-256-paramSetC (CryptoPro-B)
	CurveTC26_256_D              // id-tc26-gost-3410-2012-256-paramSetD (CryptoPro-C)
	CurveTC26_512_A              // id-tc26-gost-3410-2012-512-paramSetA
	CurveTC26_512_B              // id-tc26-gost-3410-2012-512-paramSetB
	CurveTC26_512_C              // id-tc26-gost-3410-2012-512-paramSetC
	CurveTC26_512_D              // id-tc26-gost-3410-2012-512-paramSetD (test)
	curveCount                   // sentinel; not a valid curve
)

// ErrUnknownCurve is returned when a Curve value is out of range.
var ErrUnknownCurve = errors.New("gost3410: unknown curve")

// curveNames provides human-readable names for String().
var curveNames = [curveCount]string{
	"TC26-256-A",
	"TC26-256-B",
	"TC26-256-C",
	"TC26-256-D",
	"TC26-512-A",
	"TC26-512-B",
	"TC26-512-C",
	"TC26-512-D",
}

// String returns the human-readable name of the curve (e.g. "TC26-256-A").
func (c Curve) String() string {
	if c < 0 || c >= curveCount {
		return fmt.Sprintf("Curve(%d)", int(c))
	}
	return curveNames[c]
}

// is256 returns true for the 256-bit parameter sets (indices 0..3).
func (c Curve) is256() bool { return c >= CurveTC26_256_A && c <= CurveTC26_256_D }

// is512 returns true for the 512-bit parameter sets (indices 4..7).
func (c Curve) is512() bool { return c >= CurveTC26_512_A && c <= CurveTC26_512_D }

// valid returns true if c is in range [0, curveCount).
func (c Curve) valid() bool { return c >= 0 && c < curveCount }

// Size returns the key size in bytes: 32 for 256-bit curves, 64 for 512-bit.
func (c Curve) Size() (int, error) {
	switch {
	case c.is256():
		return 32, nil
	case c.is512():
		return 64, nil
	default:
		return 0, ErrUnknownCurve
	}
}

// SignatureSize returns the signature length in bytes (2 * key size).
func (c Curve) SignatureSize() (int, error) {
	sz, err := c.Size()
	if err != nil {
		return 0, err
	}
	return 2 * sz, nil
}

// oid returns the OID string for this curve from openssl.CurveOIDs.
func (c Curve) oid() (string, error) {
	if !c.valid() {
		return "", ErrUnknownCurve
	}
	return openssl.CurveOIDs[c], nil
}

// signNID returns the appropriate GOST R 34.10-2012 signing NID.
func (c Curve) signNID() (int, error) {
	switch {
	case c.is256():
		return openssl.NID_GostR3410_2012_256, nil
	case c.is512():
		return openssl.NID_GostR3410_2012_512, nil
	default:
		return 0, ErrUnknownCurve
	}
}

// AllCurves returns all eight TC26 parameter sets.
func AllCurves() []Curve {
	all := make([]Curve, curveCount)
	for i := Curve(0); i < curveCount; i++ {
		all[i] = i
	}
	return all
}
