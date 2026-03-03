package gost3410

import (
	"crypto"
	"testing"

	"github.com/rekurt/gost-crypto/streebog"
)

// TestCryptoSignerInterface verifies that PrivKey satisfies crypto.Signer at runtime.
func TestCryptoSignerInterface(t *testing.T) {
	privKey, err := NewPrivKey(TC26_256_A)
	if err != nil {
		t.Fatalf("NewPrivKey failed: %v", err)
	}

	var signer crypto.Signer = privKey
	pub := signer.Public()
	if pub == nil {
		t.Fatal("Public() returned nil")
	}

	pubKey, ok := pub.(*PubKey)
	if !ok {
		t.Fatalf("Public() returned %T, want *PubKey", pub)
	}

	if pubKey.Curve != TC26_256_A {
		t.Errorf("curve = %v, want TC26_256_A", pubKey.Curve)
	}
	if len(pubKey.X) != 32 || len(pubKey.Y) != 32 {
		t.Error("unexpected public key coordinate size")
	}
}

// TestCryptoSignerSign verifies sign-then-verify works through the crypto.Signer interface.
func TestCryptoSignerSign(t *testing.T) {
	tests := []struct {
		name  string
		curve Curve
		hash  func([]byte) []byte
	}{
		{
			name:  "256-bit",
			curve: TC26_256_A,
			hash: func(msg []byte) []byte {
				d := streebog.Sum256(msg)
				return d[:]
			},
		},
		{
			name:  "512-bit",
			curve: TC26_512_A,
			hash: func(msg []byte) []byte {
				d := streebog.Sum512(msg)
				return d[:]
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			privKey, err := NewPrivKey(tt.curve)
			if err != nil {
				t.Fatalf("NewPrivKey failed: %v", err)
			}

			var signer crypto.Signer = privKey
			message := []byte("crypto.Signer test message")
			digest := tt.hash(message)

			// Sign through crypto.Signer interface (rand and opts are ignored)
			sig, err := signer.Sign(nil, digest, nil)
			if err != nil {
				t.Fatalf("Sign failed: %v", err)
			}

			// Verify using the typed public key
			pubKey, err := privKey.PublicKey()
			if err != nil {
				t.Fatalf("PublicKey() failed: %v", err)
			}

			valid, err := pubKey.Verify(digest, sig)
			if err != nil {
				t.Fatalf("Verify failed: %v", err)
			}
			if !valid {
				t.Error("signature from crypto.Signer.Sign did not verify")
			}
		})
	}
}
