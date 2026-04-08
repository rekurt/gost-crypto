package gost3413

import (
	"io"

	"github.com/rekurt/gost-crypto/internal/openssl"
)

// EncryptReader returns an io.Reader that encrypts all data read from src
// using the given cipher NID, key, and IV. The entire stream shares a single
// cipher context, preserving correct counter/feedback state across reads.
//
// This is the correct way to stream-encrypt data with CTR, CFB, or OFB modes.
func EncryptReader(nid int, key, iv []byte, src io.Reader) (io.Reader, error) {
	if err := openssl.Init(); err != nil {
		return nil, err
	}
	ctx, err := openssl.NewCipherCtx()
	if err != nil {
		return nil, err
	}
	if err := ctx.InitEncrypt(nid, key, iv); err != nil {
		ctx.Close()
		return nil, err
	}
	return &cipherStreamReader{ctx: ctx, src: src}, nil
}

// DecryptReader returns an io.Reader that decrypts all data read from src
// using the given cipher NID, key, and IV.
func DecryptReader(nid int, key, iv []byte, src io.Reader) (io.Reader, error) {
	if err := openssl.Init(); err != nil {
		return nil, err
	}
	ctx, err := openssl.NewCipherCtx()
	if err != nil {
		return nil, err
	}
	if err := ctx.InitDecrypt(nid, key, iv); err != nil {
		ctx.Close()
		return nil, err
	}
	return &cipherStreamReader{ctx: ctx, src: src}, nil
}

// cipherStreamReader maintains a single EVP_CIPHER_CTX across all reads,
// preserving the cipher state (counter, feedback register, etc.).
type cipherStreamReader struct {
	ctx *openssl.CipherCtx
	src io.Reader
	buf []byte // buffered output from previous Update
	eof bool
}

func (r *cipherStreamReader) Read(p []byte) (int, error) {
	// Drain buffered output first.
	if len(r.buf) > 0 {
		n := copy(p, r.buf)
		r.buf = r.buf[n:]
		return n, nil
	}
	if r.eof {
		return 0, io.EOF
	}

	// Read from source.
	chunk := make([]byte, len(p))
	n, err := r.src.Read(chunk)

	if n > 0 {
		out, cryptErr := r.ctx.Update(chunk[:n])
		if cryptErr != nil {
			return 0, cryptErr
		}
		copied := copy(p, out)
		if copied < len(out) {
			r.buf = append(r.buf[:0], out[copied:]...)
		}
		if err == io.EOF {
			// Source is done. Finalize cipher.
			tail, finalErr := r.ctx.Final()
			if finalErr != nil {
				return copied, finalErr
			}
			if len(tail) > 0 {
				r.buf = append(r.buf, tail...)
			}
			r.eof = true
			if len(r.buf) > 0 {
				return copied, nil // more data in buf, don't return EOF yet
			}
			return copied, io.EOF
		}
		if err != nil {
			return copied, err
		}
		return copied, nil
	}

	if err == io.EOF {
		// Finalize.
		tail, finalErr := r.ctx.Final()
		if finalErr != nil {
			return 0, finalErr
		}
		r.eof = true
		if len(tail) > 0 {
			n := copy(p, tail)
			if n < len(tail) {
				r.buf = append(r.buf[:0], tail[n:]...)
			}
			return n, nil
		}
		return 0, io.EOF
	}

	return 0, err
}

// Close releases the cipher context. Should be called when done reading.
func (r *cipherStreamReader) Close() error {
	if r.ctx != nil {
		r.ctx.Close()
		r.ctx = nil
	}
	return nil
}
