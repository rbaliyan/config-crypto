# CLAUDE.md

This file provides guidance to Claude Code when working with code in this repository.

## Build Commands

```bash
just test              # Run all tests
just test-race         # Run with race detector
just check             # Format, vet, and test with race detector
go test -run TestName  # Run a specific test
go test -bench=. -benchmem  # Run benchmarks
```

## Project Overview

Encryption codec for the `github.com/rbaliyan/config` library. Provides transparent encryption of configuration values via the codec system, using AES-256-GCM with envelope encryption.

## Architecture

### Codec Integration

The config library stores a codec name with every value. On read, `codec.Get(name)` resolves the codec. This package registers an encrypting codec (e.g. `"encrypted:json"`) that wraps an inner codec — `Encode` serializes then encrypts, `Decode` decrypts then deserializes. Zero changes to config or config-server needed beyond the ctx-aware `codec.Codec` interface.

### The Provider Interface

The codec depends on a single abstraction:

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

Raw key bytes never leave a Provider — callers see only Encrypt/Decrypt. `Name()` returns a short identifier used for logging/observability. `Connect()` initialises any remote connection; in-memory implementations treat it as a no-op.

Two constructors:

- `crypto.NewProvider(keyBytes, id)` — static, returns an unexported envelope Provider backed by a single 32-byte AES-256 key. The common case for single-key setups.
- `crypto.NewKeyRingProvider(initialBytes, id, rank)` — returns a `KeyRingProvider` interface for runtime key rotation via `AddKey`/`SetCurrentKey`/`RemoveKey`. All KMS packages return this type.

`KeyRingProvider` is an interface that embeds `Provider` and adds key rotation methods:

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

`NamespaceSelector` routes `Encrypt`/`Decrypt` to namespace-specific providers; `ForNamespace(ns) Provider` yields a scoped view. `RemoveAndClose` removes a namespace's provider and closes it in one step.

### Envelope Encryption

Each value gets a unique random DEK (Data Encryption Key), which is itself wrapped with the KEK (Key Encryption Key) held by the Provider. This eliminates nonce reuse risk and keeps ciphertext portable: as long as the operator holds the same KEK bytes, ciphertext decrypts regardless of where those bytes came from (AWS KMS, Vault KV, a file, etc.). DEKs are zeroed after use via `defer clear(dek)`.

### Security Properties

- **Envelope encryption**: random DEK per value, DEK wrapped with KEK
- **AAD binding**: key ID is used as GCM additional authenticated data on both DEK-wrapping and data-encryption layers, preventing key ID substitution
- **DEK zeroing**: ephemeral key material is cleared after use
- **Defensive copies**: key bytes are copied on construction; header parsing copies slices from input
- **Key material destruction**: `Provider.Close()` zeros all key material and blocks further operations; subsequent calls return `ErrProviderClosed`
- **Input validation**: `NewCodec` errors on nil inner codec or Provider; `NewProvider`/`NewKeyRingProvider`/`AddKey` validate key size, ID, and duplicate IDs

### Binary Format

Current format is **v2** (all new writes). **v1** is read-only for backward compatibility with pre-refactor ciphertext.

```
v2:
[2B magic "EC"]
[1B version = 0x02] [1B format = 0x01] [1B alg = 0x01 AES-256-GCM]
[1B key_id_len] [NB key_id UTF-8]
[12B dek_nonce] [2B encrypted_dek_len] [MB encrypted_dek]
[12B data_nonce] [remaining: ciphertext + 16B GCM tag]
```

The `format` byte is reserved for future wrapping schemes (post-quantum KEMs). `encrypted_dek` is variable-length (48B for local AES-GCM wrap). `readHeader` dispatches on the version byte; v1 uses a fixed 48B `encrypted_dek` and no `format`/`encrypted_dek_len` fields.

A golden byte-vector test (`TestDecryptV1GoldenVector` + `TestGoldenV1Drift` in `format_test.go`) locks the v1 wire format against accidental changes.

### Key Components

| File | Contents |
|------|----------|
| `crypto.go` | `Codec` struct implementing `codec.Codec` + `codec.Transformer`; wraps inner codec; threads ctx to Provider |
| `provider.go` | `Provider` interface (Name/Connect/Encrypt/Decrypt/HealthCheck/Close); `NewProvider` delegates to `keyRingProvider` with rotation methods hidden |
| `keyring_provider.go` | `KeyRingProvider` interface (embeds Provider + AddKey/SetCurrentKey/RemoveKey/CurrentKeyID/NeedsReencryption), `NewKeyRingProvider`, unexported `keyRingProvider` struct |
| `namespace_provider.go` | `NamespaceSelector`, `WithNamespaceProvider`, `WithFallbackProvider`, `ForNamespace`, `AddProvider`, `RemoveProvider`, `RemoveAndClose`, `Close` |
| `encrypt.go` | `encryptEnvelope` — generates DEK, encrypts data, wraps DEK with KEK, zeroes DEK, writes v2 header |
| `decrypt.go` | `decryptEnvelope` — reads v1 or v2 header via `readHeader`, unwraps DEK (via `keyLookupFunc`), decrypts data, zeroes DEK |
| `format.go` | Binary format constants, `header` struct, `writeHeaderV2`, `readHeader`/`readHeaderV1`/`readHeaderV2` with defensive copies |
| `errors.go` | Sentinel errors with `Is*()` helpers: `ErrKeyNotFound`, `ErrInvalidKeySize`, `ErrInvalidFormat`, `ErrUnsupportedFormat`, `ErrDecryptionFailed`, `ErrInvalidKeyID`, `ErrProviderClosed`, `ErrRemoveCurrentKey`, `ErrNoProviderForNamespace` |
| `cache.go` | `EncryptedCache` — wraps any `config.Cache`; encrypts full value payload (data, codec, type, metadata) via Provider before storage; decrypts on retrieval; treats crypto failures as cache misses; propagates provider operational failures |
| `benchmark_test.go` | Benchmarks for encode/decode at 1KB, 64KB, 1MB, and string payloads |

### KMS Provider Packages

All KMS providers are regular packages in this module (`github.com/rbaliyan/config-crypto`). No separate sub-module installs are needed; importing the package is sufficient. No SDK dependencies are introduced — each provider defines a narrow `Client` interface using only stdlib types, which the caller wires up to their SDK of choice.

| Package | Import Path | `Client` interface |
|---------|-------------|-------------------|
| `awskms/` | `github.com/rbaliyan/config-crypto/awskms` | `Decrypt(ctx, keyID string, ciphertext []byte) ([]byte, error)` |
| `gcpkms/` | `github.com/rbaliyan/config-crypto/gcpkms` | `Decrypt(ctx, resourceName string, ciphertext []byte) ([]byte, error)` |
| `azurekv/` | `github.com/rbaliyan/config-crypto/azurekv` | `UnwrapKey(ctx, keyName, keyVersion, algorithm string, ciphertext []byte) ([]byte, error)` |
| `vault/` | `github.com/rbaliyan/config-crypto/vault` | `KVMetadata` + `KVGet` (stdlib types only) |
| `gpg/` | `github.com/rbaliyan/config-crypto/gpg` | `Decrypt(ctx, ciphertext []byte) ([]byte, error)` |

Common pattern (all providers):
- Accept a `Client` interface for testability; the SDK wiring is a one-method wrapper the caller writes
- Decrypt/unwrap keys at construction using `NewKeyRingProvider` + `AddKey`, discard the client
- Decrypted key bytes are zeroed after being copied into the provider
- All return `crypto.KeyRingProvider`; `HealthCheck` is liveness-only (not remote connectivity)

Vault package (**KV v2 only**):
- `vault.New()` reads all versioned secrets at construction and returns `crypto.KeyRingProvider`
- `vault.Poll(ctx, client, ring, mount, path, interval, opts...)` starts a background goroutine that picks up new versions + promotes current; returns a `stop func()` the caller defers
- `WithRefreshErrorHandler` sets a callback for poll errors (default: slog)
- Permanently-malformed versions are retried up to `maxVersionRetries=5` times, then skipped forever
- **Note:** the prior Transit-based provider has been removed — ciphertext portability requires raw-bytes distribution

### Key Rotation Flow

1. Encrypt with `key-v1` as current
2. Rotate using `KeyRingProvider`:
   ```go
   ring, _ := crypto.NewKeyRingProvider(v2bytes, "key-v2", 2)
   ring.AddKey(v1bytes, "key-v1", 1)  // available for decryption
   ```
   Or use a KMS package that does this for you (vault with `Poll`)
3. Reads: header contains key ID → internal lookup finds old key → decrypts
4. Writes: new values encrypted with the current key

## Dependencies

Core module:
- `github.com/rbaliyan/config` — for `codec.Codec` + `codec.Transformer` interfaces only (both take `ctx context.Context`)
- Go stdlib: `crypto/aes`, `crypto/cipher`, `crypto/rand` — no third-party crypto

KMS provider packages are in the core module and add no external dependencies. The SDK wiring is a small wrapper the caller writes in their own package — see each provider's package-level doc comment for a concrete example.

## Testing

```bash
just test              # Core module tests
just test-race         # Race condition detection
just test-v            # Verbose output
just test-coverage     # Coverage report
just test-all          # All packages (equivalent to just test-race)
```

Key test scenarios:
- Round-trip: encode/decode with various types (string, struct, map, int)
- Key rotation: encrypt with old key, decrypt with provider that has both keys
- Tamper detection: modified ciphertext causes GCM authentication failure
- Key byte isolation: zeroing original bytes after `NewProvider` doesn't corrupt provider
- Input validation: nil codec/provider, invalid key sizes, empty IDs, duplicate IDs
- Error paths: Encrypt/Decrypt failure propagation, inner codec failure, key ID boundaries, closed provider rejections
- `HealthCheck`: healthy, closed-state, vault readiness (metadata error → recovered)
- `NamespaceSelector`: dispatch, fallback, runtime Add/Remove/RemoveAndClose, concurrent access, scoped-provider Close-propagation
- v1 backward compatibility: hardcoded golden hex in `format_test.go` must continue to decode
- Vault poll: picks up new versions, surfaces errors via handler, caps retries on permanent failures, Close stops the goroutine
- Config integration: full round-trip through config memory store
- Benchmarks: encode/decode at 1KB, 64KB, 1MB payload sizes
