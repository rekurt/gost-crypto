# API Reference

Module: `github.com/rekurt/gost-crypto`

## Facade package `gostcrypto`

### Types and constants

- `type Curve`
- `type PrivKey`
- `type PubKey`
- Curves:
  - `CurveTC26_256_A`, `CurveTC26_256_B`, `CurveTC26_256_C`, `CurveTC26_256_D`
  - `CurveTC26_512_A`, `CurveTC26_512_B`, `CurveTC26_512_C`, `CurveTC26_512_D`

### Functions

- `GenerateKey(c Curve) (*PrivKey, error)`
- `AllCurves() []Curve`
- `Sign(priv *PrivKey, msg []byte) ([]byte, error)`
  - auto-selects hash by curve size (`Streebog-256` for 256-bit curves, `Streebog-512` for 512-bit)
- `Verify(pub *PubKey, msg, sig []byte) (bool, error)`
- `HashSum256(data []byte) [32]byte`
- `HashSum512(data []byte) [64]byte`
- `Agree(priv *PrivKey, pub *PubKey, ukm []byte) ([]byte, error)`

### Errors (re-exported)

- `ErrUnknownCurve`
- `ErrPointNotOnCurve`
- `ErrInvalidKeySize`
- `ErrInvalidSignature`
- `ErrNilKey`
- `ErrCurveMismatch`
- `ErrEmptyUKM`

## Package `pkg/gost3410`

- Core key/signature/VKO primitives.
- Important methods:
  - `(*PrivKey).PublicKey() *PubKey`
  - `(*PrivKey).Bytes() ([]byte, error)`
  - `(*PrivKey).Zeroize()`
  - `(*PubKey).Validate() error`
- Functions:
  - `GenerateKey(c Curve) (*PrivKey, error)`
  - `SignDigest(priv *PrivKey, digest []byte) ([]byte, error)`
  - `VerifyDigest(pub *PubKey, digest, sig []byte) (bool, error)`
  - `VKO(priv *PrivKey, peerPub *PubKey, ukm []byte) ([]byte, error)`

## Package `pkg/gost3411`

- `New256() hash.Hash`
- `New512() hash.Hash`
- `Sum256(data []byte) [32]byte`
- `Sum512(data []byte) [64]byte`
- `NewHMAC256(key []byte) hash.Hash`
- `NewHMAC512(key []byte) hash.Hash`

## Package `pkg/gost3412`

- `NewKuznechik(key []byte) (cipher.Block, error)`
- Key size: 32 bytes, block size: 16 bytes.

## Package `pkg/gost3413`

- `NewMGMFromKey(key []byte) (cipher.AEAD, error)`
- AEAD parameters:
  - nonce size: 16 bytes
  - tag size: 16 bytes

## Package `pkg/kdf`

- `KDF_GOSTR3411_256(key, label, seed []byte) []byte`
- `KDF_GOSTR3411_512(key, label, seed []byte) []byte`
- `HKDF256(salt, ikm, info []byte, length int) []byte`
- `HKDF512(salt, ikm, info []byte, length int) []byte`
- `HKDFExtract256`, `HKDFExtract512`, `HKDFExpand256`, `HKDFExpand512`

## Package `pkg/hd`

- `ParsePath(path string) ([]PathComponent, error)`
- `Master(seed []byte, c Curve) (*DerivedKey, error)`
- `Derive(parent *DerivedKey, path string, c Curve) (*DerivedKey, error)`
- `(*DerivedKey).Zeroize()`

> Important current limitation: chain code derivation is deterministic, but private keys in `pkg/hd` are currently randomly generated (see package comments in `pkg/hd/hd.go`).
