package azurekv

import (
	"context"
	"fmt"

	crypto "github.com/rbaliyan/config-crypto"
)

// ListingClient extends Client with list-versions capability.
type ListingClient interface {
	Client
	// ListKeyVersions returns all enabled versions of the named key.
	ListKeyVersions(ctx context.Context, keyName string) ([]KeyVersionInfo, error)
}

// KeyVersionInfo describes one version of an Azure Key Vault key.
type KeyVersionInfo struct {
	KeyVersion string // version identifier (used as keyVersion param to UnwrapKey)
	IsCurrent  bool
}

// KeyMaterialEntry pairs a key version with its pre-wrapped data key ciphertext.
type KeyMaterialEntry struct {
	KeyVersion string // key version identifier
	Ciphertext []byte // wrapped data key
	ID         string // config-crypto key ring ID
	Algorithm  string // unwrap algorithm; default AlgorithmRSAOAEP256
	Rank       uint64
}

// NewPoller creates a crypto.FetchFn for use with crypto.Poll that
// rotates Azure Key Vault data-key material.
//
// keyName is the Azure Key Vault key name passed to ListKeyVersions
// on each poll tick.
//
// # Explicit-versioning-only limitation
//
// Azure Key Vault exposes versioned keys, but the wrapped data-key
// ciphertext for each version is not automatically enumerated by the
// SDK. The materials slice is the source of truth: each entry pairs a
// key version identifier with the already-wrapped data-key ciphertext,
// the unwrap algorithm, and the identifier/rank used inside the
// config-crypto key ring. Callers are responsible for keeping
// materials in sync with the version set they want to rotate through.
//
// Behaviour on each tick:
//   - client.ListKeyVersions returns the set of enabled key versions.
//   - For every version with a matching materials entry (by
//     KeyVersion), client.UnwrapKey is invoked (defaulting to
//     AlgorithmRSAOAEP256 when the entry's Algorithm is empty) and a
//     crypto.KeyVersion is emitted.
//   - Versions present in Key Vault but missing from materials are
//     silently skipped; versions in materials but no longer in Key
//     Vault are dropped from the current poll cycle. To retire a key
//     version, remove it from both Key Vault and materials.
func NewPoller(client ListingClient, keyName string, materials []KeyMaterialEntry) crypto.FetchFn {
	byVersion := make(map[string]KeyMaterialEntry, len(materials))
	for _, m := range materials {
		byVersion[m.KeyVersion] = m
	}

	return func(ctx context.Context) ([]crypto.KeyVersion, error) {
		infos, err := client.ListKeyVersions(ctx, keyName)
		if err != nil {
			return nil, fmt.Errorf("azurekv: list key versions: %w", err)
		}

		var versions []crypto.KeyVersion
		for _, info := range infos {
			mat, ok := byVersion[info.KeyVersion]
			if !ok {
				continue
			}
			alg := mat.Algorithm
			if alg == "" {
				alg = AlgorithmRSAOAEP256
			}
			plaintext, err := client.UnwrapKey(ctx, keyName, info.KeyVersion, alg, mat.Ciphertext)
			if err != nil {
				return nil, fmt.Errorf("azurekv: unwrap version %q: %w", info.KeyVersion, err)
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
