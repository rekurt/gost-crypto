package gost3410

import (
	"crypto/rand"
	"errors"
	"math/big"
)

// Curve identifies a TC26 curve parameter set for GOST R 34.10-2012.
type Curve int

const (
	// 256-bit curves
	TC26_256_A Curve = iota
	TC26_256_B
	TC26_256_C
	TC26_256_D
	// 512-bit curves
	TC26_512_A
	TC26_512_B
	TC26_512_C
	TC26_512_D
)

// Size returns private key size in bytes for the curve (32 or 64).
func (c Curve) Size() (int, error) {
	switch c {
	case TC26_256_A, TC26_256_B, TC26_256_C, TC26_256_D:
		return 32, nil
	case TC26_512_A, TC26_512_B, TC26_512_C, TC26_512_D:
		return 64, nil
	default:
		return 0, errors.New("unknown curve")
	}
}

// PrivKey represents a GOST R 34.10-2012 private key.
type PrivKey struct {
	D     []byte // big-endian scalar of length 32/64
	Curve Curve
}

// PubKey represents a GOST R 34.10-2012 public key.
type PubKey struct {
	X, Y  []byte // big-endian coordinates of length 32/64
	Curve Curve
}

// NewPrivKey randomly generates a new private key for the given curve.
// The generated key d satisfies 0 < d < q (curve subgroup order).
// Public key can be derived later via (*PrivKey).Public().
func NewPrivKey(c Curve) (*PrivKey, error) {
	n, err := c.Size()
	if err != nil {
		return nil, err
	}
	q, err := curveOrder(c)
	if err != nil {
		return nil, err
	}
	const maxAttempts = 128
	d := make([]byte, n)
	for i := 0; i < maxAttempts; i++ {
		if _, err := rand.Read(d); err != nil {
			return nil, err
		}
		dInt := new(big.Int).SetBytes(d)
		if dInt.Sign() > 0 && dInt.Cmp(q) < 0 {
			return &PrivKey{D: d, Curve: c}, nil
		}
	}
	return nil, errors.New("failed to generate valid private key after maximum attempts")
}

// FromRawPriv constructs a private key from raw big-endian bytes.
// Returns an error if d is zero or d >= q (curve subgroup order).
func FromRawPriv(c Curve, d []byte) (*PrivKey, error) {
	n, err := c.Size()
	if err != nil {
		return nil, err
	}
	if len(d) != n {
		return nil, errors.New("invalid private key size")
	}
	dInt := new(big.Int).SetBytes(d)
	if dInt.Sign() == 0 {
		return nil, errors.New("private key must be non-zero")
	}
	q, err := curveOrder(c)
	if err != nil {
		return nil, err
	}
	if dInt.Cmp(q) >= 0 {
		return nil, errors.New("private key must be less than curve order")
	}
	return &PrivKey{D: append([]byte(nil), d...), Curve: c}, nil
}

// FromRawPrivReduce constructs a private key by reducing d modulo (q-1) and adding 1.
// This ensures the result is always in range [1, q-1], suitable for deterministic key derivation.
func FromRawPrivReduce(c Curve, d []byte) (*PrivKey, error) {
	n, err := c.Size()
	if err != nil {
		return nil, err
	}
	if len(d) != n {
		return nil, errors.New("invalid private key size")
	}
	q, err := curveOrder(c)
	if err != nil {
		return nil, err
	}
	dInt := new(big.Int).SetBytes(d)
	qMinus1 := new(big.Int).Sub(q, big.NewInt(1))
	dInt.Mod(dInt, qMinus1)
	dInt.Add(dInt, big.NewInt(1)) // d in [1, q-1]
	dBytes := padToSize(dInt.Bytes(), n)
	return &PrivKey{D: dBytes, Curve: c}, nil
}

// ToRaw returns raw big-endian private key bytes.
func (k *PrivKey) ToRaw() []byte { return append([]byte(nil), k.D...) }

// Public derives the public key for this private key.
func (k *PrivKey) Public() (*PubKey, error) {
	x, y, err := mulBase(k.Curve, k.D)
	if err != nil {
		return nil, err
	}
	return &PubKey{X: x, Y: y, Curve: k.Curve}, nil
}

// ToUncompressed returns uncompressed public key encoding.
// If prefix==true, outputs 0x04 || X || Y similar to SEC1; else X||Y.
func (p *PubKey) ToUncompressed(prefix bool) []byte {
	n := len(p.X)
	out := make([]byte, 0, 1+2*n)
	if prefix {
		out = append(out, 0x04)
	}
	out = append(out, p.X...)
	out = append(out, p.Y...)
	return out
}

// ToCompressed returns compressed public key encoding.
// If prefix==true, outputs 0x02/0x03 || X with parity; else only X with highest bit used for parity.
func (p *PubKey) ToCompressed(prefix bool) []byte {
	n := len(p.X)
	out := make([]byte, 0, 1+n)
	yOdd := (p.Y[len(p.Y)-1] & 1) == 1
	if prefix {
		if yOdd {
			out = append(out, 0x03)
		} else {
			out = append(out, 0x02)
		}
		out = append(out, p.X...)
	} else {
		// store X and set msb to parity bit on first byte copy
		buf := append([]byte(nil), p.X...)
		if yOdd {
			buf[0] |= 0x80
		} else {
			buf[0] &^= 0x80
		}
		out = append(out, buf...)
	}
	return out
}

// FromCompressed restores a PubKey from compressed form.
// If prefix==true, expects 0x02/0x03 || X; else X with msb parity.
func FromCompressed(c Curve, enc []byte, prefix bool) (*PubKey, error) {
	n, err := c.Size()
	if err != nil {
		return nil, err
	}
	var x []byte
	var odd bool
	if prefix {
		if len(enc) != n+1 {
			return nil, errors.New("invalid compressed length")
		}
		if enc[0] != 0x02 && enc[0] != 0x03 {
			return nil, errors.New("invalid prefix")
		}
		odd = enc[0] == 0x03
		x = append([]byte(nil), enc[1:]...)
	} else {
		if len(enc) != n {
			return nil, errors.New("invalid compressed length")
		}
		x = append([]byte(nil), enc...)
		odd = (x[0] & 0x80) != 0
		x[0] &^= 0x80
	}
	y, err := recoverY(c, x, odd)
	if err != nil {
		return nil, err
	}
	return &PubKey{X: x, Y: y, Curve: c}, nil
}

// FromUncompressed parses X||Y or 0x04||X||Y
func FromUncompressed(c Curve, enc []byte, prefix bool) (*PubKey, error) {
	n, err := c.Size()
	if err != nil {
		return nil, err
	}
	if prefix {
		if len(enc) != 1+2*n || enc[0] != 0x04 {
			return nil, errors.New("invalid uncompressed")
		}
		return &PubKey{X: append([]byte(nil), enc[1:1+n]...), Y: append([]byte(nil), enc[1+n:]...), Curve: c}, nil
	}
	if len(enc) != 2*n {
		return nil, errors.New("invalid uncompressed")
	}
	return &PubKey{X: append([]byte(nil), enc[:n]...), Y: append([]byte(nil), enc[n:]...), Curve: c}, nil
}

// Backend integration (gogost) is provided in backend_*.go files.
