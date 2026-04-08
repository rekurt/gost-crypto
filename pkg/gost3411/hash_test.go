package gost3411

import (
	"testing"
)

func TestNew256_ProducesCorrectSize(t *testing.T) {
	skipIfNoEngine(t)
	h := New256()
	if h.Size() != 32 {
		t.Errorf("New256().Size() = %d, want 32", h.Size())
	}
}

func TestNew512_ProducesCorrectSize(t *testing.T) {
	skipIfNoEngine(t)
	h := New512()
	if h.Size() != 64 {
		t.Errorf("New512().Size() = %d, want 64", h.Size())
	}
}
