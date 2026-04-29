# config-crypto

[![CI](https://github.com/rbaliyan/config-crypto/actions/workflows/ci.yml/badge.svg)](https://github.com/rbaliyan/config-crypto/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/rbaliyan/config-crypto.svg)](https://pkg.go.dev/github.com/rbaliyan/config-crypto)
[![Go Report Card](https://goreportcard.com/badge/github.com/rbaliyan/config-crypto)](https://goreportcard.com/report/github.com/rbaliyan/config-crypto)
[![Release](https://img.shields.io/github/v/release/rbaliyan/config-crypto)](https://github.com/rbaliyan/config-crypto/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/rbaliyan/config-crypto/badge)](https://scorecard.dev/viewer/?uri=github.com/rbaliyan/config-crypto)

Encryption codec for the [config](https://github.com/rbaliyan/config) library. Provides transparent encryption of configuration values using AES-256-GCM with envelope encryption.

## Installation

```bash
go get github.com/rbaliyan/config-crypto
```

## Usage

```go
package main

import (
    "context"
    "fmt"

    crypto "github.com/rbaliyan/config-crypto"
    "github.com/rbaliyan/config"
    "github.com/rbaliyan/config/codec"
    "github.com/rbaliyan/config/memory"
)

func main() {
    ctx := context.Background()

    // 32-byte key for AES-256.
    key := []byte("my-32-byte-secret-key-for-aes!!") // Use a proper key in production

    // Create a Provider from raw key bytes.
    provider, err := crypto.NewProvider(key, "key-1")
    if err != nil {
        panic(err)
    }
    defer provider.Close()

    // Create and register the encrypted codec.
    encJSON, err := crypto.NewCodec(codec.Default(), provider)
    if err != nil {
        panic(err)
    }
    codec.Register(encJSON)

    // Set up a config store.
    store := memory.NewStore()
    store.Connect(ctx)
    defer store.Close(ctx)

    // Encrypt sensitive values.
    encoded, _ := encJSON.Encode(ctx, "sk-secret-api-key")
    val, _ := config.NewValueFromBytes(ctx, encoded, encJSON.Name())
    store.Set(ctx, config.DefaultNamespace, "secrets/api-key", val)

    // Read is automatic — codec name "encrypted:json" resolves via registry.
    got, _ := store.Get(ctx, config.DefaultNamespace, "secrets/api-key")
    var result string
    got.Unmarshal(ctx, &result)
    fmt.Println(result) // "sk-secret-api-key"
}
```

## How It Works

The config library stores a codec name (e.g. `"encrypted:json"`) with every value. On read, `codec.Get(name)` resolves the codec. This package provides an encrypting codec that wraps an inner codec:

- **Encode**: serialize with inner codec (JSON) → encrypt with AES-256-GCM
- **Decode**: decrypt with AES-256-GCM → deserialize with inner codec (JSON)

Each value uses **envelope encryption**: a random Data Encryption Key (DEK) encrypts the data, and the DEK itself is wrapped with your Key Encryption Key (KEK). This means:

- No nonce reuse risk (random DEK per value)
- Efficient key rotation (only re-wrap DEKs)
- Ciphertext is portable — anyone holding the same KEK bytes can decrypt, regardless of where those bytes came from (AWS KMS today, Vault KV tomorrow)

## The Provider Interface

```go
type Provider interface {
    Name() string
    Connect(ctx context.Context) error
    Encrypt(ctx context.Context, plaintext []byte) ([]byte, error)
    Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error)
    HealthCheck(ctx context.Context) error
    Close() error
}
```

`Provider` is the single abstraction the codec depends on. Raw key bytes never leave the provider — callers see only Encrypt/Decrypt. `Name()` returns a short identifier used for logging and observability. `Connect` initialises any remote connection; in-memory implementations treat it as a no-op. `HealthCheck` returns nil for a healthy provider; static providers report liveness only (not closed). `Close` zeros key material and stops any background goroutines.

Two constructors live in the core package:

- `crypto.NewProvider(keyBytes, id)` — static, from raw 32-byte AES-256 key bytes. Most common for single-key setups.
- `crypto.NewKeyRingProvider(initialBytes, id, rank)` — mutable `KeyRingProvider`, exposed so KMS packages and application code can drive runtime key rotation. `rank` is a monotonically increasing version number used by `NeedsReencryption` to determine key ordering; pass `0` when the backing store does not provide version ordering.

## Key Rotation

`KeyRingProvider` embeds `Provider` and adds key management methods:

```go
type KeyRingProvider interface {
    Provider
    AddKey(keyBytes []byte, id string, rank uint64) error
    SetCurrentKey(id string) error
    RemoveKey(id string) error
    CurrentKeyID() string
    NeedsReencryption(ciphertext []byte) (bool, error)
}
```

`rank` is used by `NeedsReencryption` to determine ordering: it returns `true` only when the ciphertext was encrypted with a key whose rank is strictly lower than the current key's rank.

```go
oldKey := []byte("original-32-byte-key-for-aes!!!")
newKey := []byte("rotated-32-byte-key-for-aes!!!!")

ring, _ := crypto.NewKeyRingProvider(newKey, "key-v2", 2)
defer ring.Close()
ring.AddKey(oldKey, "key-v1", 1)

encJSON, _ := crypto.NewCodec(codec.Default(), ring)
codec.Register(encJSON)

// Reads automatically use the correct key (key ID is in the header).
// Writes use the current key (key-v2).

// Check whether a stored ciphertext should be re-encrypted.
needsReenc, _ := ring.NeedsReencryption(storedCiphertext) // true for key-v1 ciphertext

// Remove old key when nothing in the store was encrypted with it.
ring.RemoveKey("key-v1")
```

## Namespace Routing

`NamespaceSelector` routes Encrypt/Decrypt to different providers based on namespace — useful for multi-tenant config where each tenant has its own KEK:

```go
tenantA, _ := crypto.NewProvider(keyA, "a-v1")
tenantB, _ := crypto.NewProvider(keyB, "b-v1")
fallback, _ := crypto.NewProvider(fallbackKey, "default-v1")

sel, _ := crypto.NewNamespaceSelector(
    crypto.WithNamespaceProvider("tenant-a", tenantA),
    crypto.WithNamespaceProvider("tenant-b", tenantB),
    crypto.WithFallbackProvider(fallback),
)
defer sel.Close() // also closes all registered providers

// Each namespace gets a scoped Provider.
codecA, _ := crypto.NewCodec(codec.Default(), sel.ForNamespace("tenant-a"))
codecB, _ := crypto.NewCodec(codec.Default(), sel.ForNamespace("tenant-b"))
```

`AddProvider` / `RemoveProvider` / `RemoveAndClose` manage registrations at runtime.

## Encrypted Cache

`EncryptedCache` wraps any `config.Cache` (Redis, in-memory, …) so that cached values are stored as authenticated ciphertext. The full payload — data bytes, codec name, config type, entry ID, and metadata — is encrypted by the supplied Provider before the entry reaches the backing store. Only `ExpiresAt` is forwarded to the outer wrapper so the inner cache (e.g. Redis) can enforce TTL-based eviction without decrypting.

```go
import (
    crypto "github.com/rbaliyan/config-crypto"
    configredis "github.com/rbaliyan/config/redis"
)

provider, _ := crypto.NewProvider(keyBytes, "cache-key-v1")

encCache, _ := crypto.NewEncryptedCache(
    configredis.NewCache(rdb, configredis.WithCacheTTL(5*time.Minute)),
    provider,
)

mgr, _ := config.New(
    config.WithStore(remoteStore),
    config.WithCache(encCache),
)
```

**Key rotation**: when the Provider's active key changes, previously cached ciphertext cannot be decrypted. Those entries are returned as `config.ErrNotFound`, causing the manager to re-fetch from the backing store and re-cache with the new key. No operator intervention is required — the cache re-warms transparently on the next access.

**Error handling**: cryptographic failures (wrong key, tampered ciphertext, unknown schema version) are treated as cache misses so the application keeps running. Provider operational failures (e.g. `ErrProviderClosed`) are propagated as real errors and not silently swallowed.

**Namespace-aware encryption**: combine with `NamespaceSelector` to use different keys per namespace:

```go
sel, _ := crypto.NewNamespaceSelector(
    crypto.WithNamespaceProvider("tenant-a", providerA),
    crypto.WithNamespaceProvider("tenant-b", providerB),
    crypto.WithFallbackProvider(defaultProvider),
)
encCache, _ := crypto.NewEncryptedCache(innerCache, sel)
```

## KMS Providers

All KMS providers are packages within the `github.com/rbaliyan/config-crypto` module — a single `go get github.com/rbaliyan/config-crypto` imports them all. Each provider returns a `crypto.KeyRingProvider`; internally it fetches key material from the backend and constructs a ring provider.

Each provider accepts a narrow `Client` interface using only stdlib types — you supply a one-method wrapper around your chosen SDK. This keeps the provider packages free of SDK dependencies.

```bash
go get github.com/rbaliyan/config-crypto
```

### AWS KMS

```go
import "github.com/rbaliyan/config-crypto/awskms"

// awskms.Client requires: Decrypt(ctx, keyID string, ciphertext []byte) ([]byte, error)
type myAWSClient struct{ sdk *kms.Client }
func (c *myAWSClient) Decrypt(ctx context.Context, keyID string, ciphertext []byte) ([]byte, error) {
    out, err := c.sdk.Decrypt(ctx, &kms.DecryptInput{CiphertextBlob: ciphertext, KeyId: aws.String(keyID)})
    if err != nil {
        return nil, err
    }
    return out.Plaintext, nil
}

cfg, _ := awsconfig.LoadDefaultConfig(ctx)
provider, _ := awskms.New(ctx, &myAWSClient{sdk: kms.NewFromConfig(cfg)},
    // Let KMS derive the key ID from the ciphertext context.
    awskms.WithEncryptedKey(encryptedKeyBytes, "key-1"),
    // ...or pin a specific KMS key ARN / alias:
    // awskms.WithEncryptedKeyForKMSKey(encryptedKeyBytes, "key-1", "arn:aws:kms:..."),
)
defer provider.Close()
encJSON, _ := crypto.NewCodec(codec.Default(), provider)
```

### GCP Cloud KMS

```go
import "github.com/rbaliyan/config-crypto/gcpkms"

// gcpkms.Client requires: Decrypt(ctx, resourceName string, ciphertext []byte) ([]byte, error)
type myGCPClient struct{ sdk *kms.KeyManagementClient }
func (c *myGCPClient) Decrypt(ctx context.Context, resourceName string, ciphertext []byte) ([]byte, error) {
    resp, err := c.sdk.AsymmetricDecrypt(ctx, &kmspb.AsymmetricDecryptRequest{
        Name:       resourceName,
        Ciphertext: ciphertext,
    })
    if err != nil {
        return nil, err
    }
    return resp.Plaintext, nil
}

kmsSDK, _ := kms.NewKeyManagementClient(ctx)
provider, _ := gcpkms.New(ctx, &myGCPClient{sdk: kmsSDK},
    gcpkms.WithEncryptedKey(encryptedBytes, "key-1", "projects/p/locations/l/keyRings/r/cryptoKeys/k"),
)
defer provider.Close()
```

### Azure Key Vault

```go
import "github.com/rbaliyan/config-crypto/azurekv"

// azurekv.Client requires: UnwrapKey(ctx, keyName, keyVersion, algorithm string, ciphertext []byte) ([]byte, error)
type myAzureClient struct{ sdk *azkeys.Client }
func (c *myAzureClient) UnwrapKey(ctx context.Context, keyName, keyVersion, algorithm string, ciphertext []byte) ([]byte, error) {
    resp, err := c.sdk.UnwrapKey(ctx, keyName, keyVersion, azkeys.KeyOperationParameters{
        Algorithm: (*azkeys.JSONWebKeyEncryptionAlgorithm)(&algorithm),
        Value:     ciphertext,
    }, nil)
    if err != nil {
        return nil, err
    }
    return resp.Result, nil
}

cred, _ := azidentity.NewDefaultAzureCredential(nil)
sdk, _ := azkeys.NewClient("https://my-vault.vault.azure.net/", cred, nil)
provider, _ := azurekv.New(ctx, &myAzureClient{sdk: sdk},
    azurekv.WithWrappedKey(wrappedBytes, "key-1", "my-key", "v1"),
)
defer provider.Close()
```

### HashiCorp Vault (KV v2)

Backed by the Vault KV v2 secrets engine. Each secret version becomes one key entry; the KV version number is used as the rank for `NeedsReencryption` ordering.

```go
import "github.com/rbaliyan/config-crypto/vault"

// vault.Client requires KVMetadata + KVGet (see package doc for full interface).
ring, _ := vault.New(ctx, client, "secret", "config-crypto/keys")
defer ring.Close()

// Optional: start a background goroutine that polls for new key versions.
stop, _ := vault.Poll(ctx, client, ring, "secret", "config-crypto/keys", 30*time.Second)
defer stop()
```

> **Note:** The previous Transit-based provider has been removed. Transit-wrapped ciphertext is not portable across KMS backends; this library favours raw-bytes distribution so the database of encrypted values stays portable for its full lifetime.

### GPG

```go
import "github.com/rbaliyan/config-crypto/gpg"

// gpg.Client requires: Decrypt(ctx, ciphertext []byte) ([]byte, error)
encryptedKey, _ := os.ReadFile("keys/current.key.gpg")
client := gpg.NewExecClient() // uses system gpg binary
provider, _ := gpg.New(ctx, client,
    gpg.WithEncryptedKey(encryptedKey, "key-1"),
)
defer provider.Close()
```

Suited for non-server deployments where keys are distributed as GPG-encrypted files alongside the application.

All KMS providers decrypt their key material at construction time, copy it into a local ring provider, and discard the client. For live rotation without restart, use the generic `crypto.Poll` helper with the provider-specific `NewPoller` (`awskms.NewPoller`, `gcpkms.NewPoller`, `azurekv.NewPoller`), use `vault.Poll` for HashiCorp Vault, or call `ring.AddKey`/`ring.SetCurrentKey` manually when new key material is available.

## Background Key Rotation

Two helpers drive runtime key rotation without restarting the process:

- **`crypto.Poll`** is a generic helper that periodically invokes a user-supplied `FetchFn` to discover new key versions and promote the current key. `FetchFn` returns a slice of `crypto.KeyVersion` (`ID`, `Bytes`, `Rank`, `IsCurrent`); versions already in the ring are skipped. The initial fetch is fail-fast; per-version failures are retried up to `WithPollMaxRetries` (default 5) and then permanently skipped for the lifetime of the goroutine.

- **`vault.Poll`** is a thin specialisation for the Vault KV v2 engine — it sources key versions directly from `client.KVMetadata` / `client.KVGet` without requiring the caller to write a `FetchFn`.

The AWS, GCP, and Azure provider packages ship a `NewPoller(...)` helper that returns a `crypto.FetchFn`. Pair it with `crypto.Poll`:

```go
import (
    crypto "github.com/rbaliyan/config-crypto"
    "github.com/rbaliyan/config-crypto/awskms"
)

ring, _ := awskms.New(ctx, kmsClient,
    awskms.WithEncryptedKey(v1Ciphertext, "key-v1"),
)

// Build a FetchFn from ListKeyVersions + pre-encrypted ciphertexts.
fetch := awskms.NewPoller(listingClient, "arn:aws:kms:...", []awskms.KeyMaterialEntry{
    {VersionID: "abc-1", Ciphertext: v1Ciphertext, ID: "key-v1", Rank: 1},
    {VersionID: "abc-2", Ciphertext: v2Ciphertext, ID: "key-v2", Rank: 2},
})

stop, _ := crypto.Poll(ctx, ring, 30*time.Second, fetch,
    crypto.WithPollErrorHandler(func(err error) { log.Println(err) }),
)
defer stop()
```

## Automated Re-encryption (rotation)

After the current key changes, existing ciphertext remains readable by any ring that still holds the older key (the key ID is embedded in the header), but it is not silently re-encrypted with the new key. The optional `rotation` sub-package drives that migration in the background:

```go
import "github.com/rbaliyan/config-crypto/rotation"

orch, _ := rotation.NewOrchestrator(ring, store, encJSON,
    rotation.WithNamespaces("production", "staging"),
    rotation.WithScanInterval(1*time.Hour),
    rotation.WithConcurrency(4),
    rotation.WithErrorHandler(func(ns, key string, err error) {
        log.Printf("re-encrypt %s/%s: %v", ns, key, err)
    }),
)

// Start the background scan loop.
stop, _ := orch.Start(ctx)
defer stop()

// Or trigger a single pass over a namespace synchronously.
n, _ := orch.ReencryptNamespace(ctx, "production")
```

Each scan lists values in each configured namespace, filters to those whose codec starts with `encrypted:`, and asks the ring (`NeedsReencryption`) whether the ciphertext was written with an older key rank. Stale values are decrypted and re-encrypted with the current key, then written back via `store.Set`. `Start` may only be called once per `Orchestrator`; the returned stop function cancels the scan loop and blocks until the goroutine exits.

## HealthCheck

`HealthCheck(ctx)` returns nil when the provider is usable. Its semantics depend on the backing provider:

- **Static providers** (`NewProvider`, `NewKeyRingProvider`, and all KMS wrappers) report *liveness only* — nil unless `Close` has been called. They do not contact any backend.
- **NamespaceSelector**: `sel.ForNamespace(ns).HealthCheck(ctx)` delegates to the registered provider for that namespace (or returns `ErrNoProviderForNamespace`).

## Binary Format

The encrypted payload is self-describing:

```
[2B magic "EC"]
[1B version = 0x02] [1B format = 0x01] [1B algorithm = 0x01 AES-256-GCM]
[1B key_id_len] [NB key_id UTF-8]
[12B dek_nonce] [2B encrypted_dek_len] [MB encrypted_dek]
[12B data_nonce] [remaining: ciphertext + 16B GCM tag]
```

The `format` byte is reserved for future wrapping schemes (e.g. post-quantum KEMs). `encrypted_dek` is variable-length (currently always 48B for AES-256-GCM wrap: 32B DEK + 16B tag). Overhead is ~49 + len(key_id) bytes of header plus 16B GCM tag on the payload.

**v1 compatibility:** Ciphertext produced by releases before the v2 format landed is still decryptable. The reader sniffs the version byte and dispatches to the v1 or v2 parser. `Encrypt` always writes v2.

## Security Considerations

Key material is defensively copied and zeroed when the Provider is closed (via `Close()`, DEK clearing, KMS provider intermediate buffers). However, Go's `crypto/aes` expands key bytes into an internal round-key schedule at cipher creation time and does not expose a way to zero that schedule. This means copies of key material may persist in heap memory until garbage-collected, even after `Close()` is called. This is a known limitation of the Go standard library and applies to all Go programs using `crypto/aes`. For threat models requiring guaranteed key erasure, use a hardware security module (HSM).

## Known Gaps

- **GPG provider has no background poller.** `awskms`, `gcpkms`, `azurekv`, and `vault` all offer a poll helper that plugs into `crypto.Poll`; the GPG provider does not (it is designed for file-based key distribution). Callers who want live rotation with GPG must obtain a `KeyRingProvider` via `NewKeyRingProvider` and drive `AddKey` / `SetCurrentKey` themselves when new key files arrive.
