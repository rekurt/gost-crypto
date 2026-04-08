package gost3413

import (
	"errors"
	"io"
)

// NewCTREncryptReader wraps an io.Reader with CTR-mode encryption.
// All data read from the returned reader is encrypted using the given
// CTR cipher and IV. This enables streaming encryption without buffering
// the entire input.
func NewCTREncryptReader(ctr *CTR, iv []byte, r io.Reader) io.Reader {
	return &streamCTRReader{cipher: ctr, iv: iv, src: r, encrypt: true}
}

// NewCTRDecryptReader wraps an io.Reader with CTR-mode decryption.
// In CTR mode, decryption is identical to encryption.
func NewCTRDecryptReader(ctr *CTR, iv []byte, r io.Reader) io.Reader {
	return &streamCTRReader{cipher: ctr, iv: iv, src: r, encrypt: false}
}

// NewCFBEncryptReader wraps an io.Reader with CFB-mode encryption.
func NewCFBEncryptReader(cfb *CFB, iv []byte, r io.Reader) io.Reader {
	return &streamCFBReader{cipher: cfb, iv: iv, src: r, encrypt: true}
}

// NewCFBDecryptReader wraps an io.Reader with CFB-mode decryption.
func NewCFBDecryptReader(cfb *CFB, iv []byte, r io.Reader) io.Reader {
	return &streamCFBReader{cipher: cfb, iv: iv, src: r, encrypt: false}
}

// NewOFBEncryptReader wraps an io.Reader with OFB-mode encryption.
func NewOFBEncryptReader(ofb *OFB, iv []byte, r io.Reader) io.Reader {
	return &streamOFBReader{cipher: ofb, iv: iv, src: r, encrypt: true}
}

// NewOFBDecryptReader wraps an io.Reader with OFB-mode decryption.
func NewOFBDecryptReader(ofb *OFB, iv []byte, r io.Reader) io.Reader {
	return &streamOFBReader{cipher: ofb, iv: iv, src: r, encrypt: false}
}

// --- CTR streaming ---

type streamCTRReader struct {
	cipher  *CTR
	iv      []byte
	src     io.Reader
	encrypt bool
	buf     []byte
}

func (sr *streamCTRReader) Read(p []byte) (int, error) {
	if len(sr.buf) > 0 {
		n := copy(p, sr.buf)
		sr.buf = sr.buf[n:]
		return n, nil
	}
	chunk := make([]byte, len(p))
	n, err := sr.src.Read(chunk)
	if n == 0 {
		return 0, err
	}
	var out []byte
	var cryptErr error
	if sr.encrypt {
		out, cryptErr = sr.cipher.Encrypt(sr.iv, chunk[:n])
	} else {
		out, cryptErr = sr.cipher.Decrypt(sr.iv, chunk[:n])
	}
	if cryptErr != nil {
		return 0, errors.Join(err, cryptErr)
	}
	copied := copy(p, out)
	if copied < len(out) {
		sr.buf = out[copied:]
	}
	if err != nil {
		return copied, err
	}
	return copied, nil
}

// --- CFB streaming ---

type streamCFBReader struct {
	cipher  *CFB
	iv      []byte
	src     io.Reader
	encrypt bool
	buf     []byte
}

func (sr *streamCFBReader) Read(p []byte) (int, error) {
	if len(sr.buf) > 0 {
		n := copy(p, sr.buf)
		sr.buf = sr.buf[n:]
		return n, nil
	}
	chunk := make([]byte, len(p))
	n, err := sr.src.Read(chunk)
	if n == 0 {
		return 0, err
	}
	var out []byte
	var cryptErr error
	if sr.encrypt {
		out, cryptErr = sr.cipher.Encrypt(sr.iv, chunk[:n])
	} else {
		out, cryptErr = sr.cipher.Decrypt(sr.iv, chunk[:n])
	}
	if cryptErr != nil {
		return 0, errors.Join(err, cryptErr)
	}
	copied := copy(p, out)
	if copied < len(out) {
		sr.buf = out[copied:]
	}
	if err != nil {
		return copied, err
	}
	return copied, nil
}

// --- OFB streaming ---

type streamOFBReader struct {
	cipher  *OFB
	iv      []byte
	src     io.Reader
	encrypt bool
	buf     []byte
}

func (sr *streamOFBReader) Read(p []byte) (int, error) {
	if len(sr.buf) > 0 {
		n := copy(p, sr.buf)
		sr.buf = sr.buf[n:]
		return n, nil
	}
	chunk := make([]byte, len(p))
	n, err := sr.src.Read(chunk)
	if n == 0 {
		return 0, err
	}
	var out []byte
	var cryptErr error
	if sr.encrypt {
		out, cryptErr = sr.cipher.Encrypt(sr.iv, chunk[:n])
	} else {
		out, cryptErr = sr.cipher.Decrypt(sr.iv, chunk[:n])
	}
	if cryptErr != nil {
		return 0, errors.Join(err, cryptErr)
	}
	copied := copy(p, out)
	if copied < len(out) {
		sr.buf = out[copied:]
	}
	if err != nil {
		return copied, err
	}
	return copied, nil
}
