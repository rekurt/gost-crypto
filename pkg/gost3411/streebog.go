package gost3411

import (
	"hash"
	"runtime"

	"github.com/rekurt/gost-crypto/internal/openssl"
)

// streebogHash implements hash.Hash using a buffer-and-rehash strategy.
//
// gost-engine's EVP_MD_CTX_copy_ex does not perform a proper deep copy
// of Streebog digest state, so we cannot use the clone-based approach
// for Sum() (which must not alter internal state per the hash.Hash contract).
// Instead, we keep all written data in an in-memory buffer and recompute
// the digest from scratch in Sum().
//
// Previous versions spilled large inputs to a temporary file in /tmp,
// which created a side-channel vulnerability (filesystem timing, data
// remanence on disk, predictable file name pattern). This has been
// removed in favor of unbounded in-memory buffering — the caller
// already holds the data in memory (since they passed it to Write),
// so this does not increase peak memory usage.
type streebogHash struct {
	nid       int
	buf       []byte
	size      int // 32 or 64
	blockSize int // 64 (Streebog processes 512-bit blocks)
}

// New256 returns a new hash.Hash computing Streebog-256.
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
	h.buf = append(h.buf, p...)
	return len(p), nil
}

func (h *streebogHash) cleanup() {
	if len(h.buf) > 0 {
		openssl.CleanseBytes(h.buf)
		h.buf = nil
	}
	runtime.SetFinalizer(h, nil)
}

func (h *streebogHash) Sum(b []byte) []byte {
	digest, err := openssl.HashBytes(h.nid, h.buf)
	if err != nil {
		panic("gost3411: Sum failed: " + err.Error())
	}
	return append(b, digest...)
}

func (h *streebogHash) Reset() {
	if len(h.buf) > 0 {
		openssl.CleanseBytes(h.buf)
	}
	h.buf = nil
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
