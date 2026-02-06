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

The config library stores a codec name with every value. On read, `codec.Get(name)` resolves the codec. This package registers an encrypting codec (e.g. `"encrypted:json"`) that wraps an inner codec — `Encode` serializes then encrypts, `Decode` decrypts then deserializes. Zero changes to config or config-server needed.

### Envelope Encryption

Each value gets a unique random DEK (Data Encryption Key), which is itself encrypted with the KEK (Key Encryption Key) provided by the `KeyProvider`. This eliminates nonce reuse risk and provides a clean architecture for key rotation. DEKs are zeroed after use via `defer clear(dek)`.

### Security Properties

- **Envelope encryption**: random DEK per value, DEK wrapped with KEK
- **AAD binding**: key ID is used as GCM additional authenticated data, preventing key ID substitution
- **DEK zeroing**: ephemeral key material is cleared after use
- **Defensive copies**: key bytes are copied on construction; header parsing copies slices from input
- **Input validation**: `NewCodec` panics on nil inputs; `NewStaticKeyProvider` and `WithOldKey` validate key size and ID

### Binary Format (v1)

```
[2B magic "EC"] [1B version=0x01] [1B alg=0x01 AES-256-GCM]
[1B key_id_len] [NB key_id UTF-8]
[12B dek_nonce] [48B encrypted_dek (32B DEK + 16B GCM tag)]
[12B data_nonce] [remaining: ciphertext + 16B GCM tag]
```

### Key Components

| File | Contents |
|------|----------|
| `crypto.go` | `Codec` struct implementing `codec.Codec`, wraps inner codec with encryption |
| `encrypt.go` | `encrypt()` — generates DEK, encrypts data, wraps DEK with KEK, zeroes DEK |
| `decrypt.go` | `decrypt()` — parses header, unwraps DEK, decrypts data, zeroes DEK |
| `format.go` | Binary format constants, `header` struct, `writeHeader()`, `readHeader()` with defensive copies |
| `key_provider.go` | `Key` struct, `KeyProvider` interface |
| `static_provider.go` | `StaticKeyProvider` with rotation support, key byte copying, deferred option validation |
| `errors.go` | Sentinel errors with `Is*()` helpers |
| `benchmark_test.go` | Benchmarks for encode/decode at 1KB, 64KB, 1MB, and string payloads |

### Key Rotation Flow

1. Encrypt with `key-v1` as current
2. Rotate: create provider with `key-v2` current + `WithOldKey(v1bytes, "key-v1")`
3. Reads: header contains key ID → `KeyByID` finds old key → decrypts
4. Writes: `CurrentKey` returns `key-v2` → new values encrypted with new key

## Dependencies

- `github.com/rbaliyan/config` — for `codec.Codec` interface only
- Go stdlib: `crypto/aes`, `crypto/cipher`, `crypto/rand` — no third-party crypto

## Testing

```bash
just test              # All tests
just test-race         # Race condition detection
just test-v            # Verbose output
just test-coverage     # Coverage report
```

Key test scenarios:
- Round-trip: encode/decode with various types (string, struct, map, int)
- Key rotation: encrypt with old key, decrypt with provider that has both keys
- Tamper detection: modified ciphertext causes GCM authentication failure
- Key byte isolation: zeroing original bytes doesn't corrupt provider
- Input validation: nil codec/provider, invalid key sizes, empty IDs
- Error paths: CurrentKey failure, inner codec encode/decode failure, key ID boundaries
- Config integration: full round-trip through config memory store
- Benchmarks: encode/decode at 1KB, 64KB, 1MB payload sizes
