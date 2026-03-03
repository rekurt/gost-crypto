package gost3410

import (
	"errors"
	"math/big"

	gg "github.com/ddulesov/gogost/gost3410"
)

// gogostCurve maps our Curve enum to gogost Curve objects
// Note: Only TC26_256_A, TC26_512_A/B/C are available in gogost
// Other curves (256-B/C/D, 512-D) would need to be added to gogost library
var gogostCurves = [8]*gg.Curve{
	TC26_256_A: gg.CurveIdtc26gost34102012256paramSetA(),
	TC26_256_B: nil, // Not available in gogost v1.0.0
	TC26_256_C: nil, // Not available in gogost v1.0.0
	TC26_256_D: nil, // Not available in gogost v1.0.0
	TC26_512_A: gg.CurveIdtc26gost341012512paramSetA(),
	TC26_512_B: gg.CurveIdtc26gost341012512paramSetB(),
	TC26_512_C: gg.CurveIdtc26gost34102012512paramSetC(),
	TC26_512_D: nil, // Not available in gogost v1.0.0
}

// getCurve returns the gogost Curve for our Curve enum value
func getCurve(c Curve) (*gg.Curve, error) {
	if c < 0 || c >= Curve(len(gogostCurves)) {
		return nil, errors.New("unknown curve")
	}
	gogostC := gogostCurves[c]
	if gogostC == nil {
		return nil, errors.New("curve not available in gogost backend")
	}
	return gogostC, nil
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
	return ggCurve.Q, nil
}

// mulBase multiplies the base point by scalar d and returns X, Y coordinates
// Returns big-endian bytes of fixed length (32 or 64 bytes)
func mulBase(c Curve, d []byte) (x, y []byte, err error) {
	// Create gogost private key from raw bytes
	ggCurve, err := getCurve(c)
	if err != nil {
		return nil, nil, err
	}
	mode, err := getMode(c)
	if err != nil {
		return nil, nil, err
	}

	// gogost expects little-endian, but we need to convert properly
	// Create a gogost private key to compute public key
	privKey, err := gg.NewPrivateKey(ggCurve, mode, d)
	if err != nil {
		return nil, nil, err
	}

	pubKey, err := privKey.PublicKey()
	if err != nil {
		return nil, nil, err
	}

	// gogost stores X, Y as big.Int
	// We need to convert them to big-endian bytes of fixed length
	size, _ := c.Size()
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
	size, _ := c.Size()
	return padToSize(yBig.Bytes(), size), nil
}

// padToSize pads or truncates big-endian byte representation to specific size.
// If shorter, pads with leading zeros. If longer, takes the least-significant bytes.
func padToSize(b []byte, size int) []byte {
	if len(b) == size {
		return b
	}
	if len(b) > size {
		return b[len(b)-size:]
	}
	padded := make([]byte, size)
	copy(padded[size-len(b):], b)
	return padded
}

// isOdd returns true if n is odd
func isOdd(n *big.Int) bool {
	return n.Bit(0) == 1
}

// modSqrt computes the modular square root of a modulo p using Tonelli-Shanks algorithm
// Returns nil if no square root exists
func modSqrt(a, p *big.Int) *big.Int {
	// Check if a is a quadratic residue modulo p
	// Using Euler's criterion: a^((p-1)/2) ≡ 1 (mod p)
	legendre := new(big.Int).Exp(a, new(big.Int).Div(new(big.Int).Sub(p, big.NewInt(1)), big.NewInt(2)), p)
	if legendre.Cmp(big.NewInt(1)) != 0 {
		return nil // No square root exists
	}

	// Find Q and S such that p - 1 = Q * 2^S
	Q := new(big.Int).Sub(p, big.NewInt(1))
	S := 0
	for Q.Bit(0) == 0 {
		Q.Rsh(Q, 1)
		S++
	}

	// If S == 1, then p ≡ 3 (mod 4), use simple formula
	if S == 1 {
		result := new(big.Int).Exp(a, new(big.Int).Add(new(big.Int).Rsh(p, 2), big.NewInt(1)), p)
		return result
	}

	// Find a quadratic non-residue z
	z := big.NewInt(2)
	legendre = new(big.Int).Exp(z, new(big.Int).Div(new(big.Int).Sub(p, big.NewInt(1)), big.NewInt(2)), p)
	for legendre.Cmp(big.NewInt(1)) == 0 {
		z.Add(z, big.NewInt(1))
		legendre = new(big.Int).Exp(z, new(big.Int).Div(new(big.Int).Sub(p, big.NewInt(1)), big.NewInt(2)), p)
	}

	// Tonelli-Shanks algorithm
	M := big.NewInt(int64(S))
	c := new(big.Int).Exp(z, Q, p)
	t := new(big.Int).Exp(a, Q, p)
	R := new(big.Int).Exp(a, new(big.Int).Add(new(big.Int).Rsh(Q, 1), big.NewInt(1)), p)

	for {
		if t.Cmp(big.NewInt(1)) == 0 {
			return R
		}

		// Find the least i such that t^(2^i) = 1
		i := int64(1)
		t2 := new(big.Int).Mul(t, t)
		t2.Mod(t2, p)
		for i < M.Int64() && t2.Cmp(big.NewInt(1)) != 0 {
			t2.Mul(t2, t2)
			t2.Mod(t2, p)
			i++
		}

		// Compute b = c^(2^(M-i-1))
		b := new(big.Int).Exp(big.NewInt(2), new(big.Int).Sub(new(big.Int).Sub(M, big.NewInt(i)), big.NewInt(1)), p)
		b = new(big.Int).Exp(c, b, p)

		M = big.NewInt(i)
		c.Mul(b, b)
		c.Mod(c, p)
		t.Mul(t, c)
		t.Mod(t, p)
		R.Mul(R, b)
		R.Mod(R, p)
	}
}
