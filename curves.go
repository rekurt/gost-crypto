package gostcrypto

import "github.com/rekurt/gost-crypto/pkg/gost3410"

// Curve identifies a TC26 elliptic-curve parameter set.
type Curve = gost3410.Curve

// TC26 parameter set constants (re-exported from pkg/gost3410).
const (
	CurveTC26_256_A = gost3410.CurveTC26_256_A // id-tc26-gost-3410-2012-256-paramSetA
	CurveTC26_256_B = gost3410.CurveTC26_256_B // id-tc26-gost-3410-2012-256-paramSetB
	CurveTC26_256_C = gost3410.CurveTC26_256_C // id-tc26-gost-3410-2012-256-paramSetC
	CurveTC26_256_D = gost3410.CurveTC26_256_D // id-tc26-gost-3410-2012-256-paramSetD
	CurveTC26_512_A = gost3410.CurveTC26_512_A // id-tc26-gost-3410-2012-512-paramSetA
	CurveTC26_512_B = gost3410.CurveTC26_512_B // id-tc26-gost-3410-2012-512-paramSetB
	CurveTC26_512_C = gost3410.CurveTC26_512_C // id-tc26-gost-3410-2012-512-paramSetC
	CurveTC26_512_D = gost3410.CurveTC26_512_D // id-tc26-gost-3410-2012-512-paramSetD
)

// AllCurves returns all eight TC26 parameter sets.
func AllCurves() []Curve {
	return gost3410.AllCurves()
}
