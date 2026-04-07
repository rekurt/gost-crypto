package openssl

/*
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/objects.h>

// Wrapper for EVP_get_digestbynid which is a macro in OpenSSL 3.
static const EVP_MD *go_EVP_get_digestbynid(int nid) {
	return EVP_get_digestbynid(nid);
}
*/
import "C"
import (
	"runtime"
	"sync"
	"unsafe"
)

// MDCtx wraps an EVP_MD_CTX for incremental hashing.
type MDCtx struct {
	ctx *C.EVP_MD_CTX
	md  *C.EVP_MD
}

// NewMDCtx creates a new hash context for the given digest NID.
func NewMDCtx(nid int) (*MDCtx, error) {
	if err := Init(); err != nil {
		return nil, err
	}

	md := C.go_EVP_get_digestbynid(C.int(nid))
	if md == nil {
		return nil, fmtSSLError("EVP_get_digestbynid")
	}

	ctx := C.EVP_MD_CTX_new()
	if ctx == nil {
		return nil, fmtSSLError("EVP_MD_CTX_new")
	}

	if C.EVP_DigestInit_ex(ctx, md, gostEngine) != 1 {
		C.EVP_MD_CTX_free(ctx)
		return nil, fmtSSLError("EVP_DigestInit_ex")
	}

	m := &MDCtx{ctx: ctx, md: md}
	runtime.SetFinalizer(m, (*MDCtx).finalize)
	return m, nil
}

func (m *MDCtx) Update(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	if C.EVP_DigestUpdate(m.ctx, unsafe.Pointer(&data[0]), C.size_t(len(data))) != 1 {
		return fmtSSLError("EVP_DigestUpdate")
	}
	return nil
}

func (m *MDCtx) Final() ([]byte, error) {
	size := int(C.EVP_MD_size(m.md))
	out := make([]byte, size)
	var outLen C.uint
	if C.EVP_DigestFinal_ex(m.ctx, (*C.uchar)(unsafe.Pointer(&out[0])), &outLen) != 1 {
		return nil, fmtSSLError("EVP_DigestFinal_ex")
	}
	return out[:outLen], nil
}

// Clone returns a deep copy of the current digest state using EVP_MD_CTX_copy_ex.
// The returned MDCtx is independent and must be closed by the caller.
func (m *MDCtx) Clone() (*MDCtx, error) {
	dst := C.EVP_MD_CTX_new()
	if dst == nil {
		return nil, fmtSSLError("EVP_MD_CTX_new")
	}
	if C.EVP_MD_CTX_copy_ex(dst, m.ctx) != 1 {
		C.EVP_MD_CTX_free(dst)
		return nil, fmtSSLError("EVP_MD_CTX_copy_ex")
	}
	c := &MDCtx{ctx: dst, md: m.md}
	runtime.SetFinalizer(c, (*MDCtx).finalize)
	return c, nil
}

func (m *MDCtx) Close() {
	if m.ctx != nil {
		runtime.SetFinalizer(m, nil)
		C.EVP_MD_CTX_free(m.ctx)
		m.ctx = nil
	}
}

func (m *MDCtx) finalize() {
	if m.ctx != nil {
		C.EVP_MD_CTX_free(m.ctx)
	}
}

func (m *MDCtx) Size() int      { return int(C.EVP_MD_size(m.md)) }
func (m *MDCtx) BlockSize() int { return int(C.EVP_MD_block_size(m.md)) }

func (m *MDCtx) Reset() error {
	if C.EVP_DigestInit_ex(m.ctx, m.md, gostEngine) != 1 {
		return fmtSSLError("EVP_DigestInit_ex(reset)")
	}
	return nil
}

// --- Functional API with sync.Pool ---

var mdCtxPools sync.Map // map[int]*sync.Pool

func getMDPool(nid int) *sync.Pool {
	if v, ok := mdCtxPools.Load(nid); ok {
		return v.(*sync.Pool)
	}
	p := &sync.Pool{
		New: func() any {
			ctx, err := NewMDCtx(nid)
			if err != nil {
				return nil
			}
			return ctx
		},
	}
	actual, _ := mdCtxPools.LoadOrStore(nid, p)
	return actual.(*sync.Pool)
}

// HashBytes computes a digest using sync.Pool for zero-allocation hot paths.
func HashBytes(nid int, data []byte) ([]byte, error) {
	if err := Init(); err != nil {
		return nil, err
	}

	pool := getMDPool(nid)
	obj := pool.Get()
	if obj == nil {
		return nil, &OpenSSLError{Op: "HashBytes", Text: "failed to create MDCtx from pool"}
	}
	m := obj.(*MDCtx)
	defer func() {
		if err := m.Reset(); err != nil {
			m.Close()
			return
		}
		pool.Put(m)
	}()

	if err := m.Update(data); err != nil {
		return nil, err
	}
	return m.Final()
}
