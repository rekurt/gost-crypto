package gost3413

import (
	"crypto/cipher"
	"io"
)

// EncryptReader returns an io.ReadCloser that encrypts all data read from
// src through the supplied cipher.Stream.
//
// Typical usage with the CTR / CFB / OFB mode wrappers in this package:
//
//	mode, _ := NewKuznechikCTR(key)
//	r, _ := EncryptReader(mode.Stream(iv), src)
//	io.Copy(dst, r)
//	r.Close()
//
// This preserves a single mode instance across streamed reads, so
// counter / feedback state advances correctly regardless of read-chunk
// sizes. Close() is a no-op but kept for API symmetry with the legacy
// io.ReadCloser contract.
func EncryptReader(stream cipher.Stream, src io.Reader) (io.ReadCloser, error) {
	if stream == nil {
		return nil, io.ErrUnexpectedEOF
	}
	return &cipherStreamReader{stream: stream, src: src}, nil
}

// DecryptReader is identical to EncryptReader for self-inverting modes
// (CTR / OFB) or when given an appropriately constructed stream
// decrypter (CFB decrypter, etc.). The wrapper just feeds source bytes
// through cipher.Stream.XORKeyStream in both cases.
func DecryptReader(stream cipher.Stream, src io.Reader) (io.ReadCloser, error) {
	return EncryptReader(stream, src)
}

// cipherStreamReader turns a cipher.Stream into a ReadCloser over an
// underlying io.Reader. It never allocates beyond the caller-supplied
// read buffer.
type cipherStreamReader struct {
	stream cipher.Stream
	src    io.Reader
}

func (r *cipherStreamReader) Read(p []byte) (int, error) {
	n, err := r.src.Read(p)
	if n > 0 {
		r.stream.XORKeyStream(p[:n], p[:n])
	}
	return n, err
}

func (r *cipherStreamReader) Close() error { return nil }
