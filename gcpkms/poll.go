package gcpkms

import (
	"context"
	"fmt"

	crypto "github.com/rbaliyan/config-crypto"
)

// ListingClient extends Client with list-versions capability.
type ListingClient interface {
	Client
	// ListKeyVersions returns all enabled versions of the CryptoKey.
	// resourceName is "projects/P/locations/L/keyRings/R/cryptoKeys/K".
	ListKeyVersions(ctx context.Context, resourceName string) ([]KeyVersionInfo, error)
}

// KeyVersionInfo describes one version of a GCP Cloud KMS CryptoKey.
type KeyVersionInfo struct {
	// VersionResourceName is the full resource name of this version,
	// e.g. "projects/P/locations/L/keyRings/R/cryptoKeys/K/cryptoKeyVersions/1".
	VersionResourceName string
	IsCurrent           bool
}

// KeyMaterialEntry pairs a CryptoKey version with its pre-encrypted data key ciphertext.
type KeyMaterialEntry struct {
	VersionResourceName string // full resource name of the version
	Ciphertext          []byte // encrypted data key
	ID                  string // config-crypto key ring ID
	Rank                uint64
}

// NewPoller creates a crypto.FetchFn for use with crypto.Poll that
// rotates GCP Cloud KMS data-key material.
//
// resourceName is the CryptoKey resource name (not a version name),
// e.g. "projects/P/locations/L/keyRings/R/cryptoKeys/K". It is the
// argument passed to ListKeyVersions on each poll tick.
//
// # Explicit-versioning-only limitation
//
// GCP Cloud KMS exposes CryptoKey versions, but the ciphertext
// produced for data-key wrapping is not automatically enumerated by
// the SDK. The materials slice is the source of truth: each entry
// pairs the full CryptoKeyVersion resource name with the already-
// encrypted data-key ciphertext and the identifier/rank used inside
// the config-crypto key ring. Callers are responsible for keeping
// materials in sync with the version set they want to rotate through.
//
// Behaviour on each tick:
//   - client.ListKeyVersions returns the set of enabled CryptoKey
//     versions.
//   - For every version that also has a matching materials entry (by
//     VersionResourceName), client.Decrypt is invoked to recover the
//     data-key plaintext and a crypto.KeyVersion is emitted.
//   - Versions present in KMS but missing from materials are silently
//     skipped; versions present in materials but not in KMS are
//     dropped from the current poll cycle. To retire a key version,
//     remove it from both KMS and materials.
func NewPoller(client ListingClient, resourceName string, materials []KeyMaterialEntry) crypto.FetchFn {
	byVersion := make(map[string]KeyMaterialEntry, len(materials))
	for _, m := range materials {
		byVersion[m.VersionResourceName] = m
	}

	return func(ctx context.Context) ([]crypto.KeyVersion, error) {
		infos, err := client.ListKeyVersions(ctx, resourceName)
		if err != nil {
			return nil, fmt.Errorf("gcpkms: list key versions: %w", err)
		}

		var versions []crypto.KeyVersion
		for _, info := range infos {
			mat, ok := byVersion[info.VersionResourceName]
			if !ok {
				continue
			}
			plaintext, err := client.Decrypt(ctx, info.VersionResourceName, mat.Ciphertext)
			if err != nil {
				return nil, fmt.Errorf("gcpkms: decrypt version %q: %w", info.VersionResourceName, err)
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
