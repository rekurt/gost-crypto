package gost3410

import (
	"encoding/hex"
	"testing"

	"github.com/rekurt/gost-crypto/streebog"
)

// TestTC26_256_SignVerifyVectors tests signature generation and verification with TC26_256_A curve
// While RFC 7091 provides example parameters, they are not the official TC26 parameters.
// This test validates that our implementation correctly performs sign/verify operations.
// Reference: GOST R 34.10-2012, TC26 parameter sets (http://www.tc26.ru/)
func TestTC26_256_SignVerifyVectors(t *testing.T) {
	// Test vector structure based on GOST R 34.10-2012 specification
	type testVector struct {
		name       string
		privKeyHex string // private key d in hex
		messageHex string // message to sign
		source     string // reference source
	}

	vectors := []testVector{
		{
			// Test vector using generated keys
			// This validates the sign/verify cycle works correctly
			name:       "TC26_256_A generated vector 1",
			privKeyHex: "3A929ADE789BB9BE10ED359DD39A72C11B60961F49397EEE1D19CE9891EC3B28",
			messageHex: "48656C6C6F20474F5354", // "Hello GOST"
			source:     "Generated test vector",
		},
		{
			// Additional test vector
			name:       "TC26_256_A generated vector 2",
			privKeyHex: "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
			messageHex: "54657374206D657373616765", // "Test message"
			source:     "Generated test vector",
		},
	}

	for _, tv := range vectors {
		t.Run(tv.name, func(t *testing.T) {
			// Parse private key
			privKeyBytes, err := hex.DecodeString(tv.privKeyHex)
			if err != nil {
				t.Fatalf("Failed to decode private key hex: %v", err)
			}

			privKey, err := FromRawPriv(TC26_256_A, privKeyBytes)
			if err != nil {
				t.Fatalf("Failed to create private key: %v", err)
			}

			pubKey, err := privKey.PublicKey()
			if err != nil {
				t.Fatalf("Failed to derive public key: %v", err)
			}

			// Parse message and compute digest
			message, err := hex.DecodeString(tv.messageHex)
			if err != nil {
				t.Fatalf("Failed to decode message hex: %v", err)
			}

			digest := streebog.Sum256(message)

			// Sign the message
			sig, err := privKey.SignDigest(digest[:])
			if err != nil {
				t.Fatalf("Sign failed: %v", err)
			}

			// Verify the signature should succeed
			valid, err := pubKey.Verify(digest[:], sig)
			if err != nil {
				t.Fatalf("Verify failed: %v", err)
			}

			if !valid {
				t.Error("signature verification failed for our generated signature")
			}

			// Verify should fail with different message
			wrongMessage := []byte("wrong message")
			wrongDigest := streebog.Sum256(wrongMessage)
			valid, err = pubKey.Verify(wrongDigest[:], sig)
			if err != nil {
				t.Fatalf("Verify with wrong message failed: %v", err)
			}

			if valid {
				t.Error("signature verification succeeded with wrong message - should have failed")
			}

			// Verify should fail with corrupted signature
			corruptedSig := make([]byte, len(sig))
			copy(corruptedSig, sig)
			corruptedSig[0] ^= 0xFF // flip bits
			valid, err = pubKey.Verify(digest[:], corruptedSig)
			if err != nil {
				t.Logf("Verify with corrupted signature: %v", err)
			}

			if valid {
				t.Error("signature verification succeeded with corrupted signature - should have failed")
			}
		})
	}
}

// mustDecodeHex is a helper to decode hex strings (panics on error)
func mustDecodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// TestTC26_512_SignVerifyVectors tests signature generation and verification with TC26_512_A curve
// Tests using generated keys to validate the sign/verify cycle with 512-bit keys
// Reference: GOST R 34.10-2012, TC26 parameter sets (http://www.tc26.ru/)
func TestTC26_512_SignVerifyVectors(t *testing.T) {
	// Test vector structure based on GOST R 34.10-2012 specification
	type testVector struct {
		name       string
		privKeyHex string // private key d in hex
		messageHex string // message to sign
		source     string // reference source
	}

	vectors := []testVector{
		{
			// Test vector using generated 512-bit keys
			name:       "TC26_512_A generated vector 1",
			privKeyHex: "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40",
			messageHex: "48656c6c6f20474f5354", // "Hello GOST"
			source:     "Generated test vector",
		},
		{
			// Additional 512-bit test vector
			name:       "TC26_512_A generated vector 2",
			privKeyHex: "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543200fedcba9876543210fedcba9876543210fedcba9876543210fedcba98765432ff",
			messageHex: "54657374206d657373616765", // "Test message"
			source:     "Generated test vector",
		},
	}

	for _, tv := range vectors {
		t.Run(tv.name, func(t *testing.T) {
			// Parse private key
			privKeyBytes, err := hex.DecodeString(tv.privKeyHex)
			if err != nil {
				t.Fatalf("Failed to decode private key hex: %v", err)
			}

			privKey, err := FromRawPriv(TC26_512_A, privKeyBytes)
			if err != nil {
				t.Fatalf("Failed to create private key: %v", err)
			}

			pubKey, err := privKey.PublicKey()
			if err != nil {
				t.Fatalf("Failed to derive public key: %v", err)
			}

			// Parse message and compute digest
			message, err := hex.DecodeString(tv.messageHex)
			if err != nil {
				t.Fatalf("Failed to decode message hex: %v", err)
			}

			digest := streebog.Sum512(message)

			// Sign the message
			sig, err := privKey.SignDigest(digest[:])
			if err != nil {
				t.Fatalf("Sign failed: %v", err)
			}

			// Verify the signature should succeed
			valid, err := pubKey.Verify(digest[:], sig)
			if err != nil {
				t.Fatalf("Verify failed: %v", err)
			}

			if !valid {
				t.Error("signature verification failed for our generated signature")
			}

			// Verify should fail with different message
			wrongMessage := []byte("wrong message")
			wrongDigest := streebog.Sum512(wrongMessage)
			valid, err = pubKey.Verify(wrongDigest[:], sig)
			if err != nil {
				t.Fatalf("Verify with wrong message failed: %v", err)
			}

			if valid {
				t.Error("signature verification succeeded with wrong message - should have failed")
			}
		})
	}
}

// TestStreebogTC26Vectors tests Streebog against gogost backend test vectors
// Note: Using actual gogost output as reference vectors since that's our implementation backend
func TestStreebogTC26Vectors256(t *testing.T) {
	// These test vectors are verified against gogost backend implementation
	type testVector struct {
		name     string
		input    string
		expected string
	}

	vectors := []testVector{
		{
			name:     "empty",
			input:    "",
			expected: "3f539a213e97c802cc229d474c6aa32a825a360b2a933a949fd925208d9ce1bb",
		},
		{
			name:     "abc",
			input:    "abc",
			expected: "4e2919cf137ed41ec4fb6270c61826cc4fffb660341e0af3688cd0626d23b481",
		},
	}

	for _, tv := range vectors {
		t.Run(tv.name, func(t *testing.T) {
			result := streebog.Sum256([]byte(tv.input))
			got := hex.EncodeToString(result[:])

			if got != tv.expected {
				t.Errorf("Streebog256(%q) = %s, want %s", tv.input, got, tv.expected)
			}
		})
	}
}

// DocumentationNote provides guidance on finding authoritative ТК26 vectors
// When implementing complete test coverage, refer to:
// 1. GOST R 34.10-2012 - Signature and verification algorithms (Russian standard)
// 2. GOST R 34.11-2012 - Streebog cryptographic hash function (Russian standard)
// 3. RFC 7091 - GOST R 34.10-2012 Public Key Signatures (IETF translation)
// 4. RFC 6986 - GOST R 34.11-2012 Streebog Hash Function (IETF translation)
// 5. ТК26 official website: http://www.tc26.ru/ (when accessible)
//
// Test vectors should be obtained from:
// - Official ТК26 documentation
// - GOST standards documentation
// - Verified third-party implementations with official vector validation
//
// Process for adding new vectors:
// 1. Find authoritative source
// 2. Add vector to appropriate test
// 3. Document source URL/reference in comments
// 4. Remove t.Skip() call to enable test
// 5. Verify against reference implementation
