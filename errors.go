package gostcrypto

import "github.com/rekurt/gost-crypto/pkg/gost3410"

// Sentinel errors re-exported from pkg/gost3410.
var (
	ErrUnknownCurve    = gost3410.ErrUnknownCurve
	ErrPointNotOnCurve = gost3410.ErrPointNotOnCurve
	ErrInvalidKeySize  = gost3410.ErrInvalidKeySize
	ErrInvalidSignature = gost3410.ErrInvalidSignature
	ErrNilKey          = gost3410.ErrNilKey
	ErrCurveMismatch   = gost3410.ErrCurveMismatch
	ErrEmptyUKM        = gost3410.ErrEmptyUKM
)
