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
    Encrypt(ctx context.Context, plaintext []byte) ([]byte, error)
    Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error)
    HealthCheck(ctx context.Context) error
    Close() error
}
```

`Provider` is the single abstraction the codec depends on. Raw key bytes never leave the provider — callers see only Encrypt/Decrypt. `HealthCheck` returns nil for a healthy provider; static providers report liveness only (not closed), while providers with a live backend (e.g. the Vault KV provider) also probe reachability. `Close` zeros key material and stops any background goroutines.

Two constructors live in the core package:

- `crypto.NewProvider(keyBytes, id, opts...)` — static, from raw 32-byte key bytes. Most common.
- `crypto.NewRotatingProvider(initialBytes, id, opts...)` — mutable, exposed so KMS sub-modules can drive runtime key rotation. End users rarely construct this directly.

## Key Rotation

### Static (restart-free is not needed)

```go
oldKey := []byte("original-32-byte-key-for-aes!!!")
newKey := []byte("rotated-32-byte-key-for-aes!!!!")

provider, _ := crypto.NewProvider(newKey, "key-v2",
    crypto.WithOldKey(oldKey, "key-v1"),
)
defer provider.Close()
encJSON, _ := crypto.NewCodec(codec.Default(), provider)
codec.Register(encJSON)

// Reads automatically use the correct key (key ID is in the header).
// Writes use the new key.
```

### Dynamic (runtime rotation without restart)

`RotatingProvider` supports runtime key management. End-user code typically does not construct one directly — KMS sub-modules (e.g. `vault.New` with `WithKeyVersionRefreshInterval`) build and drive one for you. If you need manual control:

```go
rp, _ := crypto.NewRotatingProvider(initialKey, "key-v1")
defer rp.Close()

// Add a new key and switch to it.
rp.AddKey(newKey, "key-v2")
rp.SetCurrentKey("key-v2")

// Remove old key when no longer needed for decryption.
rp.RemoveKey("key-v1")
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

## KMS Providers

Each KMS provider is a **separate Go module** — you only pull the SDK you need. All of them return a `crypto.Provider`; internally they construct one of the canonical Providers above using key material fetched from the backend.

### AWS KMS

```bash
go get github.com/rbaliyan/config-crypto/awskms
```

```go
import "github.com/rbaliyan/config-crypto/awskms"

cfg, _ := awsconfig.LoadDefaultConfig(ctx)
kmsClient := kms.NewFromConfig(cfg)

provider, _ := awskms.New(ctx, kmsClient,
    awskms.WithEncryptedKey(encryptedKeyBytes, "key-1"),
)
defer provider.Close()
encJSON, _ := crypto.NewCodec(codec.Default(), provider)
```

### GCP Cloud KMS

```bash
go get github.com/rbaliyan/config-crypto/gcpkms
```

```go
import "github.com/rbaliyan/config-crypto/gcpkms"

client, _ := kms.NewKeyManagementClient(ctx)
provider, _ := gcpkms.New(ctx, client,
    gcpkms.WithEncryptedKey(ciphertext, "key-1", "projects/p/locations/l/keyRings/r/cryptoKeys/k"),
)
defer provider.Close()
```

### Azure Key Vault

```bash
go get github.com/rbaliyan/config-crypto/azurekv
```

```go
import "github.com/rbaliyan/config-crypto/azurekv"

cred, _ := azidentity.NewDefaultAzureCredential(nil)
client, _ := azkeys.NewClient("https://my-vault.vault.azure.net/", cred, nil)
provider, _ := azurekv.New(ctx, client,
    azurekv.WithWrappedKey(wrappedBytes, "key-1", "my-key", "v1"),
)
defer provider.Close()
```

### HashiCorp Vault (KV v2)

```bash
go get github.com/rbaliyan/config-crypto/vault
```

Backed by the Vault KV v2 secrets engine. Each secret version becomes one key; the version number is used as the key ID. Supports optional background polling for new versions.

```go
import "github.com/rbaliyan/config-crypto/vault"

// Bring your own Client (HTTP-backed struct satisfying vault.Client).
provider, _ := vault.New(ctx, client, "secret", "config-crypto/keys",
    vault.WithKeyVersionRefreshInterval(30 * time.Second),
)
defer provider.Close() // stops the background poller
```

> **Note:** The previous Transit-based provider (which decrypted a wrapped key at startup) has been removed. Transit-wrapped ciphertext is not portable across KMS backends; this library favours raw-bytes distribution so the database of encrypted values stays portable for its full lifetime, regardless of where the operator chooses to store KEKs tomorrow.

### GPG

```bash
go get github.com/rbaliyan/config-crypto/gpg
```

```go
import "github.com/rbaliyan/config-crypto/gpg"

encryptedKey, _ := os.ReadFile("keys/current.key.gpg")
client := gpg.NewExecClient() // uses system gpg binary
provider, _ := gpg.New(ctx, client,
    gpg.WithEncryptedKey(encryptedKey, "key-1"),
)
defer provider.Close()
```

Suited for non-server deployments where keys are distributed as GPG-encrypted files alongside the application.

All KMS providers decrypt their key material at construction time, copy it into a local envelope provider, and discard the KMS client. KMS providers are static by default; for dynamic key rotation use the Vault KV provider with `WithKeyVersionRefreshInterval`, or build a `RotatingProvider` yourself and swap keys manually.

## HealthCheck

`HealthCheck(ctx)` returns nil when the provider is usable. Its semantics depend on the backing provider:

- **Static providers** (`NewProvider`, `NewRotatingProvider`, and the AWS/GCP/Azure/GPG KMS wrappers) report *liveness only* — nil unless `Close` has been called. They do not contact any backend.
- **Vault KV provider** reports *readiness* — it calls `KVMetadata` on every HealthCheck to verify Vault is reachable. Use the `ctx` deadline to bound this round-trip.
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

- **Automatic key rotation outside the Vault KV provider.** The Vault KV provider has a built-in poller (`WithKeyVersionRefreshInterval`). The AWS/GCP/Azure/GPG providers do not — callers who want rotation for those backends must build a new Provider periodically and swap it, or construct a `RotatingProvider` manually and drive `AddKey`/`SetCurrentKey` themselves. A follow-up may add parity.
