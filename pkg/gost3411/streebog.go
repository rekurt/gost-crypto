// Package gost3411 implements GOST R 34.11-2012 (Streebog) hash function
// backed by OpenSSL gost-engine.
package gost3411

import (
	"hash"
	"io"
	"os"
	"runtime"

	"github.com/rekurt/gost-crypto/internal/openssl"
)

// streebogHash implements hash.Hash using a buffer-and-rehash strategy.
//
// gost-engine's EVP_MD_CTX_copy_ex does not perform a proper deep copy
// of Streebog digest state, so we cannot use the clone-based approach
// for Sum() (which must not alter internal state per the hash.Hash contract).
// Instead, we keep a small in-memory buffer and spill larger inputs to a
// temporary file, then recompute the digest from scratch in Sum().
type streebogHash struct {
	nid       int
	buf       []byte
	spill     *os.File
	size      int // 32 or 64
	blockSize int // 64 (Streebog processes 512-bit blocks)
}

const memoryBufferLimit = 1 << 20 // 1 MiB

// New256 returns a new hash.Hash computing Streebog-256.
//
// Note: This implementation keeps up to 1 MiB in memory and spills larger
// inputs to a temporary file to avoid unbounded memory growth.
func New256() hash.Hash {
	if err := openssl.Init(); err != nil {
		panic("gost3411: failed to init OpenSSL: " + err.Error())
	}
	h := &streebogHash{
		nid:       openssl.NID_Streebog256,
		size:      32,
		blockSize: 64,
	}
	runtime.SetFinalizer(h, (*streebogHash).cleanup)
	return h
}

// New512 returns a new hash.Hash computing Streebog-512.
//
// Note: This implementation keeps up to 1 MiB in memory and spills larger
// inputs to a temporary file to avoid unbounded memory growth.
func New512() hash.Hash {
	if err := openssl.Init(); err != nil {
		panic("gost3411: failed to init OpenSSL: " + err.Error())
	}
	h := &streebogHash{
		nid:       openssl.NID_Streebog512,
		size:      64,
		blockSize: 64,
	}
	runtime.SetFinalizer(h, (*streebogHash).cleanup)
	return h
}

func (h *streebogHash) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if h.spill == nil && len(h.buf)+len(p) <= memoryBufferLimit {
		h.buf = append(h.buf, p...)
		return len(p), nil
	}
	if err := h.ensureSpillFile(); err != nil {
		panic("gost3411: failed to spill hash input: " + err.Error())
	}
	if _, err := h.spill.Write(p); err != nil {
		panic("gost3411: failed to spill hash input: " + err.Error())
	}
	return len(p), nil
}

func (h *streebogHash) ensureSpillFile() error {
	if h.spill != nil {
		return nil
	}
	f, err := os.CreateTemp("", "gost3411-*")
	if err != nil {
		return err
	}
	if len(h.buf) > 0 {
		if _, err := f.Write(h.buf); err != nil {
			_ = f.Close()
			_ = os.Remove(f.Name())
			return err
		}
		openssl.CleanseBytes(h.buf)
		h.buf = nil
	}
	h.spill = f
	return nil
}

func (h *streebogHash) hashFromSpill() []byte {
	if _, err := h.spill.Seek(0, io.SeekStart); err != nil {
		panic("gost3411: failed to seek spill file: " + err.Error())
	}
	ctx, err := openssl.NewMDCtx(h.nid)
	if err != nil {
		panic("gost3411: failed to create hash context: " + err.Error())
	}
	defer ctx.Close()
	buf := make([]byte, 32*1024)
	for {
		n, rerr := h.spill.Read(buf)
		if n > 0 {
			if err := ctx.Update(buf[:n]); err != nil {
				panic("gost3411: failed to update hash context: " + err.Error())
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			panic("gost3411: failed to read spill file: " + rerr.Error())
		}
	}
	digest, err := ctx.Final()
	if err != nil {
		panic("gost3411: failed to finalize hash context: " + err.Error())
	}
	return digest
}

func (h *streebogHash) closeResources() {
	if h.spill != nil {
		name := h.spill.Name()
		_ = h.spill.Close()
		_ = os.Remove(name)
		h.spill = nil
	}
	if len(h.buf) > 0 {
		openssl.CleanseBytes(h.buf)
		h.buf = nil
	}
}

func (h *streebogHash) cleanup() {
	h.closeResources()
	runtime.SetFinalizer(h, nil)
}

func (h *streebogHash) Sum(b []byte) []byte {
	var digest []byte
	if h.spill != nil {
		digest = h.hashFromSpill()
	} else {
		var err error
		digest, err = openssl.HashBytes(h.nid, h.buf)
		if err != nil {
			panic("gost3411: Sum failed: " + err.Error())
		}
	}
	return append(b, digest...)
}

func (h *streebogHash) Reset() {
	h.closeResources()
}

func (h *streebogHash) Size() int      { return h.size }
func (h *streebogHash) BlockSize() int { return h.blockSize }

// Sum256 returns the Streebog-256 digest of data.
func Sum256(data []byte) [32]byte {
	digest, err := openssl.HashBytes(openssl.NID_Streebog256, data)
	if err != nil {
		panic("gost3411: Streebog-256 failed: " + err.Error())
	}
	var out [32]byte
	copy(out[:], digest)
	return out
}

// Sum512 returns the Streebog-512 digest of data.
func Sum512(data []byte) [64]byte {
	digest, err := openssl.HashBytes(openssl.NID_Streebog512, data)
	if err != nil {
		panic("gost3411: Streebog-512 failed: " + err.Error())
	}
	var out [64]byte
	copy(out[:], digest)
	return out
}
