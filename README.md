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

    // Create a 32-byte key for AES-256
    key := []byte("my-32-byte-secret-key-for-aes!!") // Use a proper key in production

    // Create a key provider
    provider, err := crypto.NewStaticKeyProvider(key, "key-1")
    if err != nil {
        panic(err)
    }

    // Create and register the encrypted codec
    encJSON := crypto.NewCodec(codec.JSON(), provider)
    codec.Register(encJSON)

    // Set up a config store
    store := memory.NewStore()
    store.Connect(ctx)
    defer store.Close(ctx)

    // Encrypt sensitive values
    encoded, _ := encJSON.Encode("sk-secret-api-key")
    val, _ := config.NewValueFromBytes(encoded, encJSON.Name())
    store.Set(ctx, config.DefaultNamespace, "secrets/api-key", val)

    // Read is automatic — codec name "encrypted:json" resolves via registry
    got, _ := store.Get(ctx, config.DefaultNamespace, "secrets/api-key")
    var result string
    got.Unmarshal(&result)
    fmt.Println(result) // "sk-secret-api-key"
}
```

## How It Works

The config library stores a codec name (e.g. `"encrypted:json"`) with every value. On read, `codec.Get(name)` resolves the codec. This package provides an encrypting codec that wraps an inner codec:

- **Encode**: serialize with inner codec (JSON) → encrypt with AES-256-GCM
- **Decode**: decrypt with AES-256-GCM → deserialize with inner codec (JSON)

Each value uses **envelope encryption**: a random Data Encryption Key (DEK) encrypts the data, and the DEK itself is encrypted with your Key Encryption Key (KEK). This means:

- No nonce reuse risk (random DEK per value)
- Efficient key rotation (only re-wrap DEKs)
- KMS-ready architecture

## Key Rotation

```go
// Original setup
oldKey := []byte("original-32-byte-key-for-aes!!!")
oldProvider, _ := crypto.NewStaticKeyProvider(oldKey, "key-v1")

// Rotate: new key is current, old key available for decryption
newKey := []byte("rotated-32-byte-key-for-aes!!!!")
newProvider, _ := crypto.NewStaticKeyProvider(newKey, "key-v2",
    crypto.WithOldKey(oldKey, "key-v1"),
)
encJSON := crypto.NewCodec(codec.JSON(), newProvider)
codec.Register(encJSON)

// Reads automatically use the correct key (key ID is in the encrypted header)
// Writes use the new key
```

### Full Re-encryption

To re-encrypt all values with the new key:

1. Read all values (auto-decrypts with old key via header key ID)
2. Re-set them (auto-encrypts with new current key)

## Key Material Cleanup

When a provider is no longer needed, call `Destroy()` to zero all key material in memory:

```go
provider, _ := crypto.NewStaticKeyProvider(key, "key-1")
defer provider.Destroy()
```

After `Destroy()`, all operations return `ErrProviderDestroyed`.

## KMS Providers

Each KMS provider is a **separate Go module** — you only pull the SDK you need.

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
encJSON := crypto.NewCodec(codec.JSON(), provider)
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
```

### HashiCorp Vault (Transit)

```bash
go get github.com/rbaliyan/config-crypto/vault
```

```go
import "github.com/rbaliyan/config-crypto/vault"

// Implement the vault.Client interface with your preferred HTTP client
provider, _ := vault.New(ctx, client,
    vault.WithEncryptedKey("vault:v1:base64data", "key-1", "my-transit-key"),
)
```

All KMS providers decrypt keys at construction time and cache them in a `StaticKeyProvider`. The KMS client is not retained after construction. Key rotation works the same way — pass multiple keys, first is current.

## Custom Key Providers

Implement the `KeyProvider` interface for other key management systems:

```go
type KeyProvider interface {
    CurrentKey() (crypto.Key, error)
    KeyByID(id string) (crypto.Key, error)
}
```

## Binary Format

The encrypted payload uses a self-describing binary format:

```
[2B magic "EC"] [1B version] [1B algorithm]
[1B key_id_len] [NB key_id]
[12B dek_nonce] [48B encrypted_dek]
[12B data_nonce] [remaining: ciphertext + GCM tag]
```

Overhead is ~93 + len(key_id) bytes per value (header + GCM authentication tag).
