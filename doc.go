// Package gostcrypto implements Russian GOST cryptographic standards
// backed by CryptoPro CSP (CAPILite) and CryptoPro CAdES via CGO.
//
// This library provides a production-ready Go implementation of the
// complete Russian cryptographic toolkit:
//
//   - GOST R 34.10-2012 digital signatures (all 8 TC26 elliptic curves)
//   - GOST R 34.11-2012 Streebog hash function (256-bit and 512-bit)
//   - GOST R 34.12-2015 Kuznechik block cipher ([cipher.Block] interface)
//   - GOST R 34.13-2015 MGM authenticated encryption ([cipher.AEAD] interface)
//   - VKO key agreement (GOST R 34.10-2012 ECDH)
//   - Hierarchical deterministic (HD) key derivation with BIP32-style paths
//   - HKDF and KDF_GOSTR3411 key derivation functions
//
// Primitive operations (Streebog, GOST 34.10-2012 sign/verify/VKO, raw
// Kuznechik/Magma block cipher, IMIT MAC) are delegated to CryptoPro
// CSP via CAPILite. CMS / CAdES-BES signatures are produced by
// CryptoPro's CAdES library (libcades). Higher-level cipher modes
// (CBC/CTR/CFB/OFB and MGM) are implemented in pure Go on top of the
// raw block cipher. The library has zero external Go dependencies.
//
// # Quick Start
//
// Generate a key pair and sign a message:
//
//	priv, err := gostcrypto.GenerateKey(gostcrypto.CurveTC26_256_A)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer priv.Zeroize()
//
//	sig, err := gostcrypto.Sign(priv, []byte("Hello, GOST!"))
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	ok, err := gostcrypto.Verify(priv.PublicKey(), []byte("Hello, GOST!"), sig)
//
// # Supported Curves
//
// The library supports all 8 standardized TC26 parameter sets:
// [CurveTC26_256_A], [CurveTC26_256_B], [CurveTC26_256_C], [CurveTC26_256_D]
// (256-bit) and [CurveTC26_512_A], [CurveTC26_512_B], [CurveTC26_512_C],
// [CurveTC26_512_D] (512-bit).
//
// # Hash Auto-Selection
//
// The high-level [Sign] and [Verify] functions automatically select the
// appropriate Streebog variant based on the key's curve size:
// Streebog-256 for 256-bit curves, Streebog-512 for 512-bit curves.
//
// # Requirements
//
// CryptoPro CSP 5.0+ for Linux installed under /opt/cprocsp/ and CGO enabled.
// See https://github.com/rekurt/gost-crypto/blob/master/docs/DEPLOYMENT.md
// for setup instructions.
package gostcrypto
