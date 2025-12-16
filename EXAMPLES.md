# Extended Usage Examples

This document provides advanced usage patterns and real-world scenarios for the gost-crypto library.

**[📖 README (English)](README.md)** | **[📖 README (Russian)](README.ru.md)** | **[📚 Documentation Index](DOCUMENTATION.md)** | **[🔧 API Reference](API.md)** | **[🤝 Contributing](CONTRIBUTING.md)**

## Table of Contents

- [Error Handling Patterns](#error-handling-patterns)
- [Key Management Best Practices](#key-management-best-practices)
- [Working with Multiple Keys](#working-with-multiple-keys)
- [Building a Signature Verification Service](#building-a-signature-verification-service)
- [HD Wallet Implementation](#hd-wallet-implementation)
- [Batch Document Processing](#batch-document-processing)
- [Key Exchange and Transport](#key-exchange-and-transport)

## Error Handling Patterns

### Graceful Error Handling

```go
package main

import (
    "fmt"
    "log"
    "gost-crypto/gost3410"
    "gost-crypto/gostcrypto"
)

func safeSign(privKey *gost3410.PrivKey, message []byte) ([]byte, error) {
    if privKey == nil {
        return nil, fmt.Errorf("private key is nil")
    }

    if len(message) == 0 {
        return nil, fmt.Errorf("message is empty")
    }

    opts := &gostcrypto.Options{Hash: gost3410.Streebog256}
    signature, err := gostcrypto.Sign(privKey, message, opts)
    if err != nil {
        log.Printf("failed to sign message: %v", err)
        return nil, fmt.Errorf("signing failed: %w", err)
    }

    return signature, nil
}

func safeVerify(pubKey *gost3410.PubKey, message, signature []byte) (bool, error) {
    if pubKey == nil {
        return false, fmt.Errorf("public key is nil")
    }

    if len(message) == 0 {
        return false, fmt.Errorf("message is empty")
    }

    if len(signature) == 0 {
        return false, fmt.Errorf("signature is empty")
    }

    opts := &gostcrypto.Options{Hash: gost3410.Streebog256}
    valid, err := gostcrypto.Verify(pubKey, message, signature, opts)
    if err != nil {
        log.Printf("verification error: %v", err)
        return false, fmt.Errorf("verification failed: %w", err)
    }

    return valid, nil
}
```

### Retry Logic with Exponential Backoff

```go
package main

import (
    "fmt"
    "time"
)

func retrySignWithBackoff(operation func() ([]byte, error), maxRetries int) ([]byte, error) {
    var lastErr error
    backoff := time.Millisecond * 10

    for attempt := 0; attempt < maxRetries; attempt++ {
        result, err := operation()
        if err == nil {
            return result, nil
        }

        lastErr = err
        if attempt < maxRetries-1 {
            time.Sleep(backoff)
            backoff *= 2
        }
    }

    return nil, fmt.Errorf("failed after %d attempts: %w", maxRetries, lastErr)
}
```

## Key Management Best Practices

### Key Storage Wrapper

```go
package main

import (
    "crypto/rand"
    "encoding/hex"
    "fmt"
    "gost-crypto/gost3410"
)

type KeyManager struct {
    privKey *gost3410.PrivKey
    pubKey  *gost3410.PubKey
}

func NewKeyManager(curve gost3410.Curve) (*KeyManager, error) {
    privKey, _, err := gost3410.NewPrivKey(curve)
    if err != nil {
        return nil, err
    }

    pubKey, err := privKey.Public()
    if err != nil {
        return nil, err
    }

    return &KeyManager{
        privKey: privKey,
        pubKey:  pubKey,
    }, nil
}

func (km *KeyManager) GetPublicKey() *gost3410.PubKey {
    return km.pubKey
}

func (km *KeyManager) ExportPublicKey(compressed bool) string {
    var key []byte
    if compressed {
        key = km.pubKey.ToCompressed(true)
    } else {
        key = km.pubKey.ToUncompressed(true)
    }
    return hex.EncodeToString(key)
}

func (km *KeyManager) Sign(message []byte) ([]byte, error) {
    opts := &gostcrypto.Options{Hash: gost3410.Streebog256}
    return gostcrypto.Sign(km.privKey, message, opts)
}

func (km *KeyManager) Verify(message, signature []byte) (bool, error) {
    opts := &gostcrypto.Options{Hash: gost3410.Streebog256}
    return gostcrypto.Verify(km.pubKey, message, signature, opts)
}

func (km *KeyManager) RotateKey(curve gost3410.Curve) error {
    newKM, err := NewKeyManager(curve)
    if err != nil {
        return err
    }

    km.privKey = newKM.privKey
    km.pubKey = newKM.pubKey
    return nil
}

// IMPORTANT: Never call this in production
// This is only for testing/demonstration
func (km *KeyManager) ExportPrivateKeyForBackup() string {
    return hex.EncodeToString(km.privKey.D)
}
```

### Key Pool for Concurrent Operations

```go
package main

import (
    "sync"
    "gost-crypto/gost3410"
)

type KeyPool struct {
    keys    chan *gost3410.PrivKey
    created int
    max     int
    mu      sync.Mutex
}

func NewKeyPool(size int, curve gost3410.Curve) (*KeyPool, error) {
    pool := &KeyPool{
        keys: make(chan *gost3410.PrivKey, size),
        max:  size,
    }

    for i := 0; i < size; i++ {
        privKey, _, err := gost3410.NewPrivKey(curve)
        if err != nil {
            return nil, err
        }

        pool.keys <- privKey
        pool.created++
    }

    return pool, nil
}

func (p *KeyPool) AcquireKey() *gost3410.PrivKey {
    return <-p.keys
}

func (p *KeyPool) ReleaseKey(key *gost3410.PrivKey) {
    p.keys <- key
}

func (p *KeyPool) Stats() (created, available int) {
    p.mu.Lock()
    defer p.mu.Unlock()
    return p.created, len(p.keys)
}
```

## Working with Multiple Keys

### Multi-Signature Support

```go
package main

import (
    "fmt"
    "gost-crypto/gost3410"
    "gost-crypto/gostcrypto"
)

type MultiSigner struct {
    signers map[string]*gost3410.PrivKey
    curve   gost3410.Curve
}

func NewMultiSigner(curve gost3410.Curve) *MultiSigner {
    return &MultiSigner{
        signers: make(map[string]*gost3410.PrivKey),
        curve:   curve,
    }
}

func (ms *MultiSigner) AddSigner(id string) error {
    privKey, _, err := gost3410.NewPrivKey(ms.curve)
    if err != nil {
        return err
    }

    ms.signers[id] = privKey
    return nil
}

func (ms *MultiSigner) SignWithAll(message []byte) (map[string][]byte, error) {
    signatures := make(map[string][]byte)
    opts := &gostcrypto.Options{Hash: gost3410.Streebog256}

    for id, privKey := range ms.signers {
        sig, err := gostcrypto.Sign(privKey, message, opts)
        if err != nil {
            return nil, err
        }
        signatures[id] = sig
    }

    return signatures, nil
}

func (ms *MultiSigner) VerifyAllSignatures(message []byte, signatures map[string][]byte) (map[string]bool, error) {
    results := make(map[string]bool)
    opts := &gostcrypto.Options{Hash: gost3410.Streebog256}

    for id, privKey := range ms.signers {
        pubKey, err := privKey.Public()
        if err != nil {
            return nil, err
        }

        sig, exists := signatures[id]
        if !exists {
            results[id] = false
            continue
        }

        valid, err := gostcrypto.Verify(pubKey, message, sig, opts)
        if err != nil {
            results[id] = false
        } else {
            results[id] = valid
        }
    }

    return results, nil
}
```

## Building a Signature Verification Service

### HTTP-Based Verification Service

```go
package main

import (
    "encoding/base64"
    "encoding/json"
    "fmt"
    "log"
    "net/http"
    "gost-crypto/gost3410"
    "gost-crypto/gostcrypto"
)

type VerificationRequest struct {
    PublicKeyHex string `json:"public_key"`
    MessageBase64 string `json:"message"`
    SignatureBase64 string `json:"signature"`
}

type VerificationResponse struct {
    Valid bool   `json:"valid"`
    Error string `json:"error,omitempty"`
}

type VerificationService struct {
    curve gost3410.Curve
}

func NewVerificationService(curve gost3410.Curve) *VerificationService {
    return &VerificationService{curve: curve}
}

func (vs *VerificationService) HandleVerifyRequest(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    var req VerificationRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(VerificationResponse{
            Valid: false,
            Error: "Invalid request format",
        })
        return
    }

    // Decode public key
    pubKeyBytes, err := base64.StdEncoding.DecodeString(req.PublicKeyHex)
    if err != nil {
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(VerificationResponse{
            Valid: false,
            Error: "Invalid public key encoding",
        })
        return
    }

    // Recover public key from compressed format
    pubKey, err := gost3410.FromCompressed(vs.curve, pubKeyBytes, true)
    if err != nil {
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(VerificationResponse{
            Valid: false,
            Error: "Failed to recover public key",
        })
        return
    }

    // Decode message and signature
    message, err := base64.StdEncoding.DecodeString(req.MessageBase64)
    if err != nil {
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(VerificationResponse{
            Valid: false,
            Error: "Invalid message encoding",
        })
        return
    }

    signature, err := base64.StdEncoding.DecodeString(req.SignatureBase64)
    if err != nil {
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(VerificationResponse{
            Valid: false,
            Error: "Invalid signature encoding",
        })
        return
    }

    // Verify signature
    opts := &gostcrypto.Options{Hash: gost3410.Streebog256}
    valid, err := gostcrypto.Verify(pubKey, message, signature, opts)
    if err != nil {
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(VerificationResponse{
            Valid: false,
            Error: fmt.Sprintf("Verification error: %v", err),
        })
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(VerificationResponse{
        Valid: valid,
    })
}
```

## HD Wallet Implementation

### Account Management

```go
package main

import (
    "encoding/hex"
    "fmt"
    "gost-crypto/gost3410"
    "gost-crypto/gostcrypto"
    "gost-crypto/kdf/hd"
)

type HDAccount struct {
    masterKey   *gost3410.PrivKey
    chainCode   []byte
    accountPath string
}

func NewHDAccount(seed []byte, accountIndex int) (*HDAccount, error) {
    masterKey, chainCode, err := hd.Master(seed, gost3410.Streebog256)
    if err != nil {
        return nil, err
    }

    // BIP44-like path: m/44'/283'/accountIndex'/0/0
    // 283 is a placeholder coin type
    accountPath := fmt.Sprintf("m/44'/283'/%d'/0", accountIndex)

    accountKey, accountChain, err := hd.Derive(masterKey, chainCode, accountPath, gost3410.Streebog256)
    if err != nil {
        return nil, err
    }

    return &HDAccount{
        masterKey:   accountKey,
        chainCode:   accountChain,
        accountPath: accountPath,
    }, nil
}

func (acc *HDAccount) DeriveAddress(index int) (*gost3410.PubKey, error) {
    // Derive from account path m/account'/0/index
    path := fmt.Sprintf("%s/%d", acc.accountPath, index)

    addressKey, _, err := hd.Derive(acc.masterKey, acc.chainCode, path, gost3410.Streebog256)
    if err != nil {
        return nil, err
    }

    return addressKey.Public()
}

func (acc *HDAccount) SignTransaction(transactionData []byte, addressIndex int) ([]byte, error) {
    // Derive key for this address
    path := fmt.Sprintf("%s/%d", acc.accountPath, addressIndex)

    signingKey, _, err := hd.Derive(acc.masterKey, acc.chainCode, path, gost3410.Streebog256)
    if err != nil {
        return nil, err
    }

    opts := &gostcrypto.Options{Hash: gost3410.Streebog256}
    return gostcrypto.Sign(signingKey, transactionData, opts)
}

type MultiAccountWallet struct {
    accounts map[int]*HDAccount
}

func NewMultiAccountWallet(seed []byte, numAccounts int) (*MultiAccountWallet, error) {
    wallet := &MultiAccountWallet{
        accounts: make(map[int]*HDAccount),
    }

    for i := 0; i < numAccounts; i++ {
        account, err := NewHDAccount(seed, i)
        if err != nil {
            return nil, err
        }
        wallet.accounts[i] = account
    }

    return wallet, nil
}

func (w *MultiAccountWallet) GetAddress(accountIndex, addressIndex int) (*gost3410.PubKey, error) {
    account, exists := w.accounts[accountIndex]
    if !exists {
        return nil, fmt.Errorf("account %d not found", accountIndex)
    }

    return account.DeriveAddress(addressIndex)
}

func (w *MultiAccountWallet) SignWithAccount(accountIndex int, transaction []byte, addressIndex int) ([]byte, error) {
    account, exists := w.accounts[accountIndex]
    if !exists {
        return nil, fmt.Errorf("account %d not found", accountIndex)
    }

    return account.SignTransaction(transaction, addressIndex)
}
```

## Batch Document Processing

### Document Processor with Receipts

```go
package main

import (
    "crypto/sha256"
    "encoding/hex"
    "fmt"
    "sync"
    "time"
    "gost-crypto/gost3410"
    "gost-crypto/gostcrypto"
)

type SignedDocument struct {
    ID         string
    Content    []byte
    Signature  []byte
    Timestamp  time.Time
    PublicKey  string
}

type DocumentProcessor struct {
    privKey *gost3410.PrivKey
    pubKey  *gost3410.PubKey
    mu      sync.Mutex
    results []SignedDocument
}

func NewDocumentProcessor(curve gost3410.Curve) (*DocumentProcessor, error) {
    privKey, _, err := gost3410.NewPrivKey(curve)
    if err != nil {
        return nil, err
    }

    pubKey, err := privKey.Public()
    if err != nil {
        return nil, err
    }

    return &DocumentProcessor{
        privKey: privKey,
        pubKey:  pubKey,
        results: make([]SignedDocument, 0),
    }, nil
}

func (dp *DocumentProcessor) ProcessDocument(id string, content []byte) (*SignedDocument, error) {
    opts := &gostcrypto.Options{Hash: gost3410.Streebog256}

    signature, err := gostcrypto.Sign(dp.privKey, content, opts)
    if err != nil {
        return nil, err
    }

    pubKeyHex := hex.EncodeToString(dp.pubKey.ToCompressed(true))

    doc := SignedDocument{
        ID:        id,
        Content:   content,
        Signature: signature,
        Timestamp: time.Now(),
        PublicKey: pubKeyHex,
    }

    dp.mu.Lock()
    dp.results = append(dp.results, doc)
    dp.mu.Unlock()

    return &doc, nil
}

func (dp *DocumentProcessor) ProcessBatch(documents map[string][]byte) ([]SignedDocument, error) {
    results := make([]SignedDocument, 0, len(documents))
    errors := make([]error, 0)

    var wg sync.WaitGroup
    var mu sync.Mutex

    for id, content := range documents {
        wg.Add(1)

        go func(docID string, docContent []byte) {
            defer wg.Done()

            doc, err := dp.ProcessDocument(docID, docContent)
            if err != nil {
                mu.Lock()
                errors = append(errors, err)
                mu.Unlock()
                return
            }

            mu.Lock()
            results = append(results, *doc)
            mu.Unlock()
        }(id, content)
    }

    wg.Wait()

    if len(errors) > 0 {
        return nil, fmt.Errorf("batch processing failed with %d errors", len(errors))
    }

    return results, nil
}

func (dp *DocumentProcessor) VerifyDocument(doc *SignedDocument) (bool, error) {
    opts := &gostcrypto.Options{Hash: gost3410.Streebog256}
    return gostcrypto.Verify(dp.pubKey, doc.Content, doc.Signature, opts)
}

func (dp *DocumentProcessor) GenerateReceipt() string {
    dp.mu.Lock()
    defer dp.mu.Unlock()

    receipt := fmt.Sprintf("Document Batch Receipt\n")
    receipt += fmt.Sprintf("Total Documents: %d\n", len(dp.results))
    receipt += fmt.Sprintf("Processor Public Key: %s\n\n", hex.EncodeToString(dp.pubKey.ToCompressed(true)))
    receipt += "Documents:\n"

    for i, doc := range dp.results {
        hash := sha256.Sum256(doc.Content)
        receipt += fmt.Sprintf("%d. ID: %s, Hash: %s, Signed: %s\n",
            i+1, doc.ID, hex.EncodeToString(hash[:8]), doc.Timestamp.Format(time.RFC3339))
    }

    return receipt
}
```

## Key Exchange and Transport

### Secure Key Exchange Protocol

```go
package main

import (
    "encoding/hex"
    "fmt"
    "gost-crypto/gost3410"
    "gost-crypto/gostcrypto"
)

type KeyExchangeParticipant struct {
    privKey *gost3410.PrivKey
    pubKey  *gost3410.PubKey
    id      string
}

func NewKeyExchangeParticipant(id string, curve gost3410.Curve) (*KeyExchangeParticipant, error) {
    privKey, _, err := gost3410.NewPrivKey(curve)
    if err != nil {
        return nil, err
    }

    pubKey, err := privKey.Public()
    if err != nil {
        return nil, err
    }

    return &KeyExchangeParticipant{
        privKey: privKey,
        pubKey:  pubKey,
        id:      id,
    }, nil
}

func (kep *KeyExchangeParticipant) ExportPublicKey() string {
    return hex.EncodeToString(kep.pubKey.ToCompressed(true))
}

func (kep *KeyExchangeParticipant) SignPublicKey(otherParticipantPubKey string) (string, error) {
    opts := &gostcrypto.Options{Hash: gost3410.Streebog256}

    signature, err := gostcrypto.Sign(kep.privKey, []byte(otherParticipantPubKey), opts)
    if err != nil {
        return "", err
    }

    return hex.EncodeToString(signature), nil
}

type KeyExchangeProtocol struct {
    participant1 *KeyExchangeParticipant
    participant2 *KeyExchangeParticipant
}

func NewKeyExchangeProtocol(p1, p2 *KeyExchangeParticipant) *KeyExchangeProtocol {
    return &KeyExchangeProtocol{
        participant1: p1,
        participant2: p2,
    }
}

func (kep *KeyExchangeProtocol) ExecuteExchange() (bool, error) {
    // Step 1: Each participant exports their public key
    pubKey1 := kep.participant1.ExportPublicKey()
    pubKey2 := kep.participant2.ExportPublicKey()

    fmt.Printf("Participant 1 public key: %s\n", pubKey1)
    fmt.Printf("Participant 2 public key: %s\n", pubKey2)

    // Step 2: Each participant signs the other's public key
    sig1, err := kep.participant1.SignPublicKey(pubKey2)
    if err != nil {
        return false, err
    }

    sig2, err := kep.participant2.SignPublicKey(pubKey1)
    if err != nil {
        return false, err
    }

    fmt.Printf("Participant 1 signature: %s\n", sig1)
    fmt.Printf("Participant 2 signature: %s\n", sig2)

    // Step 3: Mutual verification of signatures
    opts := &gostcrypto.Options{Hash: gost3410.Streebog256}

    sig1Bytes, _ := hex.DecodeString(sig1)
    valid1, err := gostcrypto.Verify(kep.participant2.pubKey, []byte(pubKey2), sig1Bytes, opts)
    if err != nil || !valid1 {
        return false, fmt.Errorf("signature 1 verification failed")
    }

    sig2Bytes, _ := hex.DecodeString(sig2)
    valid2, err := gostcrypto.Verify(kep.participant1.pubKey, []byte(pubKey1), sig2Bytes, opts)
    if err != nil || !valid2 {
        return false, fmt.Errorf("signature 2 verification failed")
    }

    fmt.Println("Key exchange completed successfully!")
    return true, nil
}
```

These examples demonstrate various patterns and techniques for using gost-crypto in real-world applications.
