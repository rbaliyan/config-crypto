package awskms

import (
	"context"
	"fmt"

	crypto "github.com/rbaliyan/config-crypto"
)

// ListingClient extends Client with the ability to enumerate key versions.
// Implement this interface when you want to drive background rotation with
// crypto.Poll + NewPoller. The SDK wiring is still a one-method-per-API
// wrapper — the AWS KMS SDK itself does not natively expose a single
// "list all versions of a data key" call, so the concrete behaviour
// (e.g. mapping a KMS multi-region alias to a set of version IDs) is
// caller-defined.
type ListingClient interface {
	Client
	// ListKeyVersions returns all available versions of the given KMS key alias/ARN.
	ListKeyVersions(ctx context.Context, kmsKeyID string) ([]KeyVersionInfo, error)
	// DecryptVersion decrypts ciphertext produced by a specific key version.
	DecryptVersion(ctx context.Context, kmsKeyID, versionID string, ciphertext []byte) (plaintext []byte, err error)
}

// KeyVersionInfo describes one version of an AWS KMS key.
type KeyVersionInfo struct {
	VersionID string
	IsCurrent bool
}

// KeyMaterialEntry pairs a KMS version with its pre-encrypted data key ciphertext.
type KeyMaterialEntry struct {
	VersionID  string // KMS key version ID
	Ciphertext []byte // encrypted data key bytes
	ID         string // identifier in the config-crypto key ring
	Rank       uint64 // ordering rank (higher = newer)
}

// NewPoller creates a crypto.FetchFn for use with crypto.Poll that
// rotates AWS KMS data-key material.
//
// # Explicit-versioning-only limitation
//
// AWS KMS does not expose a native "list all versions of a data key"
// API. The materials slice is the source of truth: each entry pairs a
// KMS key version ID with the already-encrypted data-key ciphertext
// blob and its identifier/rank inside the config-crypto key ring.
// Callers are responsible for keeping materials in sync with the
// set of KMS versions they wish to rotate through — typically by
// writing new (versionID, ciphertext) pairs to an external store
// (S3, Secrets Manager, a config namespace) whenever a new data key
// is issued and reloading them before each Poll tick.
//
// Behaviour on each tick:
//   - client.ListKeyVersions enumerates the KMS versions currently
//     visible to the caller's implementation.
//   - For every version returned that also has a matching materials
//     entry (by VersionID), client.DecryptVersion is invoked to
//     recover the data-key plaintext and a crypto.KeyVersion is
//     emitted for the poller.
//   - Versions present in KMS but not in materials are silently
//     skipped, and versions present in materials but no longer in
//     KMS are dropped from the poll cycle. To retire a key, remove
//     it from both the KMS side and materials.
//
// kmsKeyID is the KMS key ARN or alias passed to ListKeyVersions.
func NewPoller(client ListingClient, kmsKeyID string, materials []KeyMaterialEntry) crypto.FetchFn {
	byVersion := make(map[string]KeyMaterialEntry, len(materials))
	for _, m := range materials {
		byVersion[m.VersionID] = m
	}

	return func(ctx context.Context) ([]crypto.KeyVersion, error) {
		infos, err := client.ListKeyVersions(ctx, kmsKeyID)
		if err != nil {
			return nil, fmt.Errorf("awskms: list key versions: %w", err)
		}

		var versions []crypto.KeyVersion
		for _, info := range infos {
			mat, ok := byVersion[info.VersionID]
			if !ok {
				continue
			}
			plaintext, err := client.DecryptVersion(ctx, kmsKeyID, info.VersionID, mat.Ciphertext)
			if err != nil {
				return nil, fmt.Errorf("awskms: decrypt version %q: %w", info.VersionID, err)
			}
			versions = append(versions, crypto.KeyVersion{
				ID:        mat.ID,
				Bytes:     plaintext,
				Rank:      mat.Rank,
				IsCurrent: info.IsCurrent,
			})
		}
		return versions, nil
	}
}
