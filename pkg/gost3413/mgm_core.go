package gost3413

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
)

// This file implements GOST R 34.13-2015 MGM (Multilinear Galois Mode)
// as a pure-Go AEAD construction parameterised over any cipher.Block
// with block size 8 (Magma) or 16 (Kuznechik).
//
// Rationale: CryptoPro CSP does not expose MGM as a native CAPILite
// cipher mode, so MGM must be assembled in software on top of the raw
// ECB block cipher. pkg/gost3412's NewKuznechik / NewMagma return a
// standard cipher.Block backed by CryptoPro CSP's raw ECB primitive —
// that is exactly what this file consumes.
//
// Reference: GOST R 34.13-2015, Appendix A "Multilinear Galois Mode".
//
// IMPORTANT: This is a fresh pure-Go implementation written during the
// OpenSSL → CryptoPro CSP migration. The Seal / Open pair is internally
// self-consistent (round-trip tests pass), but the byte-level counter
// construction and GF(2^n) field polynomial reduction have not yet been
// validated against external MGM known-answer test vectors. A follow-up
// patch should add KAT vectors from the TC26 MGM specification.

// mgmCore is a generic MGM AEAD. blockSize must be 8 or 16.
type mgmCore struct {
	block     cipher.Block
	blockSize int
	nonceSize int
	tagSize   int
}

// newMGMCore builds an MGM instance. The nonce and tag sizes both equal
// the underlying block size per GOST R 34.13-2015.
func newMGMCore(block cipher.Block) (*mgmCore, error) {
	bs := block.BlockSize()
	if bs != 8 && bs != 16 {
		return nil, errors.New("gost3413: MGM requires an 8- or 16-byte block cipher")
	}
	return &mgmCore{
		block:     block,
		blockSize: bs,
		nonceSize: bs,
		tagSize:   bs,
	}, nil
}

// incCounter increments the big-endian counter in b[start:] in place.
// Used to advance the MGM encryption / authentication sub-counters.
func incCounter(b []byte) {
	for i := len(b) - 1; i >= 0; i-- {
		b[i]++
		if b[i] != 0 {
			return
		}
	}
}

// gfMul performs GF(2^n) multiplication for MGM where n ∈ {64, 128}.
// a and b are byte slices of length n/8 interpreted as big-endian.
// Result is written into out (same length).
//
// Field polynomials used by GOST MGM:
//   - n=128: x^128 + x^7 + x^2 + x^1 + 1  (reduction constant 0x87)
//   - n=64 : x^64 + x^4 + x^3 + x^1 + 1   (reduction constant 0x1b)
//
// The algorithm is the standard shift-and-add (Russian peasant) loop
// over bits of `a`, XOR-accumulating shifted `b` into the result and
// reducing modulo the field polynomial whenever the top bit of `b`
// spills out on a left shift.
func gfMul(out, a, b []byte) {
	n := len(a)
	if n != len(b) || n != len(out) {
		panic("gost3413: gfMul size mismatch")
	}
	var reductionLow byte
	switch n {
	case 16:
		reductionLow = 0x87
	case 8:
		reductionLow = 0x1b
	default:
		panic("gost3413: gfMul: unsupported field size")
	}

	// Work in a local copy of b so we can shift it left in place.
	work := make([]byte, n)
	copy(work, b)

	// Clear result.
	for i := range out {
		out[i] = 0
	}

	// Iterate over bits of a from MSB of a[0] to LSB of a[n-1].
	for i := 0; i < n; i++ {
		for bit := 7; bit >= 0; bit-- {
			if (a[i]>>uint(bit))&1 == 1 {
				for k := 0; k < n; k++ {
					out[k] ^= work[k]
				}
			}
			// Shift work left by 1.
			carry := byte(0)
			for k := n - 1; k >= 0; k-- {
				newCarry := work[k] >> 7
				work[k] = (work[k] << 1) | carry
				carry = newCarry
			}
			if carry != 0 {
				work[n-1] ^= reductionLow
			}
		}
	}
}

// xor writes dst = a XOR b. dst, a, b must all be the same length.
func xor(dst, a, b []byte) {
	for i := range dst {
		dst[i] = a[i] ^ b[i]
	}
}

// Seal implements AEAD encryption.
//
// MGM layout:
//   - Nonce N has length blockSize; the MSB of N must be 0.
//   - Encryption counter Z_1 starts at 0 || N[1:] (MSB cleared) plus "1"
//     in the high-counter half. We encrypt E_K(Z_i) to get keystream.
//   - Authentication counter Z'_1 starts at 1 || N[1:] (MSB set); we
//     encrypt E_K(Z'_i) to get authentication multipliers H_i.
//   - Tag T = E_K(Σ H_i·A_i ⊕ H_final·len_block)
//
// For the sake of compactness we use simultaneous counter increment:
// keystream blocks and auth multipliers are generated in lock-step.
func (m *mgmCore) Seal(dst, nonce, plaintext, additionalData []byte) ([]byte, error) {
	if len(nonce) != m.nonceSize {
		return nil, errors.New("gost3413: wrong MGM nonce length")
	}
	if nonce[0]&0x80 != 0 {
		return nil, errors.New("gost3413: MGM nonce MSB must be 0")
	}

	// Initial counters.
	encCtr := make([]byte, m.blockSize)
	copy(encCtr, nonce)
	encCtr[0] &^= 0x80 // ensure MSB=0

	authCtr := make([]byte, m.blockSize)
	copy(authCtr, nonce)
	authCtr[0] |= 0x80 // ensure MSB=1

	// Encrypt initial encCtr to establish the starting keystream block
	// (MGM increments the low half, not the whole block).
	encBlk := make([]byte, m.blockSize)
	authBlk := make([]byte, m.blockSize)

	ciphertext := make([]byte, len(plaintext))
	sum := make([]byte, m.blockSize)
	tmp := make([]byte, m.blockSize)

	// --- Process AAD ---
	authAAD(m, additionalData, authCtr, authBlk, sum, tmp)

	// --- Encrypt plaintext ---
	offset := 0
	for offset < len(plaintext) {
		// Encrypt keystream block.
		m.block.Encrypt(encBlk, encCtr)
		remaining := len(plaintext) - offset
		if remaining >= m.blockSize {
			for i := 0; i < m.blockSize; i++ {
				ciphertext[offset+i] = plaintext[offset+i] ^ encBlk[i]
			}
			// Authenticate full cipher block via multiplication.
			m.block.Encrypt(authBlk, authCtr)
			gfMul(tmp, authBlk, ciphertext[offset:offset+m.blockSize])
			xor(sum, sum, tmp)
			offset += m.blockSize
		} else {
			// Final short block.
			for i := 0; i < remaining; i++ {
				ciphertext[offset+i] = plaintext[offset+i] ^ encBlk[i]
			}
			padded := make([]byte, m.blockSize)
			copy(padded, ciphertext[offset:offset+remaining])
			m.block.Encrypt(authBlk, authCtr)
			gfMul(tmp, authBlk, padded)
			xor(sum, sum, tmp)
			offset += remaining
		}
		// Advance counters (low half only; high half is fixed).
		incHalf(encCtr, false) // low half
		incHalf(authCtr, true) // low half
	}

	// --- Finalise: length block ---
	lenBlock := make([]byte, m.blockSize)
	writeLengths(lenBlock, len(additionalData)*8, len(plaintext)*8, m.blockSize)
	m.block.Encrypt(authBlk, authCtr)
	gfMul(tmp, authBlk, lenBlock)
	xor(sum, sum, tmp)

	// Tag = E_K(sum).
	tag := make([]byte, m.blockSize)
	m.block.Encrypt(tag, sum)

	// Append ciphertext + tag to dst.
	ret := make([]byte, 0, len(dst)+len(ciphertext)+m.tagSize)
	ret = append(ret, dst...)
	ret = append(ret, ciphertext...)
	ret = append(ret, tag...)
	return ret, nil
}

// Open implements AEAD decryption.
func (m *mgmCore) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != m.nonceSize {
		return nil, errors.New("gost3413: wrong MGM nonce length")
	}
	if nonce[0]&0x80 != 0 {
		return nil, errors.New("gost3413: MGM nonce MSB must be 0")
	}
	if len(ciphertext) < m.tagSize {
		return nil, errors.New("gost3413: ciphertext too short for MGM tag")
	}

	tag := ciphertext[len(ciphertext)-m.tagSize:]
	ct := ciphertext[:len(ciphertext)-m.tagSize]

	encCtr := make([]byte, m.blockSize)
	copy(encCtr, nonce)
	encCtr[0] &^= 0x80
	authCtr := make([]byte, m.blockSize)
	copy(authCtr, nonce)
	authCtr[0] |= 0x80

	encBlk := make([]byte, m.blockSize)
	authBlk := make([]byte, m.blockSize)
	sum := make([]byte, m.blockSize)
	tmp := make([]byte, m.blockSize)

	authAAD(m, additionalData, authCtr, authBlk, sum, tmp)

	plaintext := make([]byte, len(ct))
	offset := 0
	for offset < len(ct) {
		remaining := len(ct) - offset
		m.block.Encrypt(authBlk, authCtr)
		if remaining >= m.blockSize {
			gfMul(tmp, authBlk, ct[offset:offset+m.blockSize])
			xor(sum, sum, tmp)
			m.block.Encrypt(encBlk, encCtr)
			for i := 0; i < m.blockSize; i++ {
				plaintext[offset+i] = ct[offset+i] ^ encBlk[i]
			}
			offset += m.blockSize
		} else {
			padded := make([]byte, m.blockSize)
			copy(padded, ct[offset:offset+remaining])
			gfMul(tmp, authBlk, padded)
			xor(sum, sum, tmp)
			m.block.Encrypt(encBlk, encCtr)
			for i := 0; i < remaining; i++ {
				plaintext[offset+i] = ct[offset+i] ^ encBlk[i]
			}
			offset += remaining
		}
		incHalf(encCtr, false)
		incHalf(authCtr, true)
	}

	lenBlock := make([]byte, m.blockSize)
	writeLengths(lenBlock, len(additionalData)*8, len(ct)*8, m.blockSize)
	m.block.Encrypt(authBlk, authCtr)
	gfMul(tmp, authBlk, lenBlock)
	xor(sum, sum, tmp)

	expected := make([]byte, m.blockSize)
	m.block.Encrypt(expected, sum)

	// Constant-time compare.
	var diff byte
	for i := 0; i < m.tagSize; i++ {
		diff |= expected[i] ^ tag[i]
	}
	if diff != 0 {
		return nil, errors.New("gost3413: MGM authentication failed")
	}

	ret := make([]byte, 0, len(dst)+len(plaintext))
	ret = append(ret, dst...)
	ret = append(ret, plaintext...)
	return ret, nil
}

// authAAD folds the additional authenticated data into the running MGM
// authentication sum. Each full block is multiplied by its authentication
// multiplier H_i and XOR-accumulated; a trailing short block is zero-padded.
func authAAD(m *mgmCore, aad []byte, authCtr, authBlk, sum, tmp []byte) {
	if len(aad) == 0 {
		return
	}
	offset := 0
	for offset < len(aad) {
		remaining := len(aad) - offset
		m.block.Encrypt(authBlk, authCtr)
		if remaining >= m.blockSize {
			gfMul(tmp, authBlk, aad[offset:offset+m.blockSize])
			xor(sum, sum, tmp)
			offset += m.blockSize
		} else {
			padded := make([]byte, m.blockSize)
			copy(padded, aad[offset:offset+remaining])
			gfMul(tmp, authBlk, padded)
			xor(sum, sum, tmp)
			offset += remaining
		}
		incHalf(authCtr, true)
	}
}

// incHalf increments either the high half (auth) or the low half (enc)
// of a counter in place. The two halves are treated as independent
// big-endian counters occupying the upper / lower `blockSize/2` bytes.
//
// Per GOST 34.13-2015 Appendix A, the encryption counter mutates the
// low half and the authentication counter mutates the high half — but
// with the MSB of the whole block fixed to indicate "enc vs auth".
// We preserve the MSB via a post-increment mask.
func incHalf(ctr []byte, auth bool) {
	half := len(ctr) / 2
	var (
		start int
		mask  byte
	)
	if auth {
		start = 0
		mask = 0x80
	} else {
		start = half
		mask = 0x00
	}
	for i := start + half - 1; i >= start; i-- {
		ctr[i]++
		if ctr[i] != 0 {
			break
		}
	}
	if auth {
		ctr[0] |= mask
	} else {
		ctr[0] &^= 0x80
	}
}

// writeLengths encodes the AAD bit length and plaintext bit length into
// the tag length-block, big-endian halves. For a 16-byte block that is
// 8+8 bytes; for 8 bytes that is 4+4.
func writeLengths(buf []byte, aadBits, ptBits, blockSize int) {
	half := blockSize / 2
	switch half {
	case 8:
		binary.BigEndian.PutUint64(buf[:8], uint64(aadBits))
		binary.BigEndian.PutUint64(buf[8:16], uint64(ptBits))
	case 4:
		binary.BigEndian.PutUint32(buf[:4], uint32(aadBits))
		binary.BigEndian.PutUint32(buf[4:8], uint32(ptBits))
	default:
		panic("gost3413: unsupported MGM block size")
	}
}
