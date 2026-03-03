package gost3410

import (
	"crypto/rand"
	"errors"
	"math/big"

	gg "github.com/ddulesov/gogost/gost3410"
)

// gogostCurveFactories maps our Curve enum to gogost curve constructor functions.
// Fresh instances are created per call to avoid data races on mutable scratch
// fields (t, tx, ty) inside gogost Curve.add() during concurrent operations.
var gogostCurveFactories = [8]func() *gg.Curve{
	TC26_256_A: gg.CurveIdtc26gost34102012256paramSetA,
	TC26_256_B: nil, // Not available in gogost v1.0.0
	TC26_256_C: nil, // Not available in gogost v1.0.0
	TC26_256_D: nil, // Not available in gogost v1.0.0
	TC26_512_A: gg.CurveIdtc26gost341012512paramSetA,
	TC26_512_B: gg.CurveIdtc26gost341012512paramSetB,
	TC26_512_C: gg.CurveIdtc26gost34102012512paramSetC,
	TC26_512_D: nil, // Not available in gogost v1.0.0
}

// getCurve returns a fresh gogost Curve for our Curve enum value.
func getCurve(c Curve) (*gg.Curve, error) {
	if c < 0 || c >= Curve(len(gogostCurveFactories)) {
		return nil, errors.New("unknown curve")
	}
	factory := gogostCurveFactories[c]
	if factory == nil {
		return nil, errors.New("curve not available in gogost backend")
	}
	return factory(), nil
}

// getMode returns the gogost Mode for our Curve
func getMode(c Curve) (gg.Mode, error) {
	n, err := c.Size()
	if err != nil {
		return 0, err
	}
	switch n {
	case 32:
		return gg.Mode2001, nil // Mode2001 = 32 bytes
	case 64:
		return gg.Mode2012, nil // Mode2012 = 64 bytes
	default:
		return 0, errors.New("invalid curve size")
	}
}

// curveOrder returns the subgroup order q for the given curve.
func curveOrder(c Curve) (*big.Int, error) {
	ggCurve, err := getCurve(c)
	if err != nil {
		return nil, err
	}
	return new(big.Int).Set(ggCurve.Q), nil
}

// reversedCopy returns a new byte slice with bytes in reverse order.
// gogost uses little-endian wire format for keys; our library uses big-endian.
func reversedCopy(b []byte) []byte {
	r := make([]byte, len(b))
	for i := range b {
		r[i] = b[len(b)-1-i]
	}
	return r
}

// mulBase multiplies the base point by scalar d and returns X, Y coordinates.
// d is big-endian; returned x, y are big-endian of fixed length (32 or 64 bytes).
func mulBase(c Curve, d []byte) (x, y []byte, err error) {
	ggCurve, err := getCurve(c)
	if err != nil {
		return nil, nil, err
	}
	mode, err := getMode(c)
	if err != nil {
		return nil, nil, err
	}

	// gogost NewPrivateKey expects little-endian; reverse our big-endian D
	privKey, err := gg.NewPrivateKey(ggCurve, mode, reversedCopy(d))
	if err != nil {
		return nil, nil, err
	}

	pubKey, err := privKey.PublicKey()
	if err != nil {
		return nil, nil, err
	}

	// gogost stores X, Y as big.Int; convert to big-endian bytes of fixed length
	size, err := c.Size()
	if err != nil {
		return nil, nil, err
	}
	x = padToSize(pubKey.X.Bytes(), size)
	y = padToSize(pubKey.Y.Bytes(), size)

	return x, y, nil
}

// recoverY recovers the Y coordinate from X coordinate and oddness flag
// for the elliptic curve equation: y² ≡ x³ + ax + b (mod p)
func recoverY(c Curve, x []byte, odd bool) ([]byte, error) {
	ggCurve, err := getCurve(c)
	if err != nil {
		return nil, err
	}

	// Convert x from big-endian bytes to big.Int
	xBig := new(big.Int).SetBytes(x)

	// Compute y² = x³ + ax + b (mod p)
	ySquared := new(big.Int)
	xCubed := new(big.Int).Mul(xBig, xBig)
	xCubed.Mul(xCubed, xBig)
	xCubed.Mod(xCubed, ggCurve.P)

	axPlusBTerm := new(big.Int).Mul(ggCurve.A, xBig)
	axPlusBTerm.Add(axPlusBTerm, ggCurve.B)
	axPlusBTerm.Mod(axPlusBTerm, ggCurve.P)

	ySquared.Add(xCubed, axPlusBTerm)
	ySquared.Mod(ySquared, ggCurve.P)

	// Compute y = sqrt(ySquared) mod p using Tonelli-Shanks algorithm
	yBig := modSqrt(ySquared, ggCurve.P)
	if yBig == nil {
		return nil, errors.New("no square root exists")
	}

	// Check parity and select correct y
	if odd != isOdd(yBig) {
		yBig.Sub(ggCurve.P, yBig)
	}

	// Convert to big-endian bytes
	size, err := c.Size()
	if err != nil {
		return nil, err
	}
	return padToSize(yBig.Bytes(), size), nil
}

// padToSize pads or truncates big-endian byte representation to specific size.
// If shorter, pads with leading zeros. If longer, takes the least-significant bytes.
// Always returns a new slice (copy) to avoid shared memory.
func padToSize(b []byte, size int) []byte {
	if len(b) == size {
		return append([]byte(nil), b...)
	}
	if len(b) > size {
		return append([]byte(nil), b[len(b)-size:]...)
	}
	padded := make([]byte, size)
	copy(padded[size-len(b):], b)
	return padded
}

// isOdd returns true if n is odd
func isOdd(n *big.Int) bool {
	return n.Bit(0) == 1
}

// modSqrt computes the modular square root of a modulo p.
// Returns nil if no square root exists.
func modSqrt(a, p *big.Int) *big.Int {
	return new(big.Int).ModSqrt(a, p)
}

// backendSign computes a GOST R 34.10-2012 signature using the gogost backend.
// Returns signature in s||r format (gogost native), which the caller must reorder to r||s.
func backendSign(c Curve, d, digest []byte) ([]byte, error) {
	ggCurve, err := getCurve(c)
	if err != nil {
		return nil, err
	}

	mode, err := getMode(c)
	if err != nil {
		return nil, err
	}

	ggPrivKey, err := gg.NewPrivateKey(ggCurve, mode, reversedCopy(d))
	if err != nil {
		return nil, err
	}

	return ggPrivKey.SignDigest(digest, rand.Reader)
}

// backendVerify checks a GOST R 34.10-2012 signature using the gogost backend.
// Expects signature in s||r format (gogost native), which the caller must prepare from r||s.
func backendVerify(c Curve, x, y, digest, sig []byte) (bool, error) {
	ggCurve, err := getCurve(c)
	if err != nil {
		return false, err
	}

	mode, err := getMode(c)
	if err != nil {
		return false, err
	}

	keySize, err := c.Size()
	if err != nil {
		return false, err
	}

	// gogost.NewPublicKey expects raw format as: X||Y with both coordinates reversed to little-endian
	rawKey := make([]byte, 2*keySize)
	for i := 0; i < keySize; i++ {
		rawKey[i] = x[keySize-1-i]
	}
	for i := 0; i < keySize; i++ {
		rawKey[keySize+i] = y[keySize-1-i]
	}

	ggPubKey, err := gg.NewPublicKey(ggCurve, mode, rawKey)
	if err != nil {
		return false, err
	}

	return ggPubKey.VerifyDigest(digest, sig)
}
