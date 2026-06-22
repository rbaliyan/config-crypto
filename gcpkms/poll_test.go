package gcpkms

import (
	"context"
	"errors"
	"testing"

	crypto "github.com/rbaliyan/config-crypto"
)

// listingMock implements ListingClient for exercising NewPoller's FetchFn.
// GCP's NewPoller calls client.Decrypt (from the base Client) for each
// version, so the embedded mockClient already provides the decrypt path; the
// failOn field controls per-version decrypt failures.
type listingMock struct {
	mockClient
	infos   []KeyVersionInfo
	listErr error
}

func (m *listingMock) ListKeyVersions(_ context.Context, _ string) ([]KeyVersionInfo, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	return m.infos, nil
}

func TestNewPoller_FetchFn(t *testing.T) {
	t.Parallel()

	const v1Name = resourceName + "/cryptoKeyVersions/1"
	const v2Name = resourceName + "/cryptoKeyVersions/2"

	materials := []KeyMaterialEntry{
		{VersionResourceName: v1Name, Ciphertext: []byte("enc-v1"), ID: "key-v1", Rank: 1},
		{VersionResourceName: v2Name, Ciphertext: []byte("enc-v2"), ID: "key-v2", Rank: 2},
	}
	keyMap := map[string][]byte{
		"enc-v1": makeKey(1),
		"enc-v2": makeKey(2),
	}

	cases := []struct {
		name    string
		infos   []KeyVersionInfo
		listErr error
		failOn  string // ciphertext the mock Decrypt rejects
		wantErr bool
		want    []crypto.KeyVersion
	}{
		{
			name:    "list error",
			listErr: errors.New("kms: unavailable"),
			wantErr: true,
		},
		{
			name: "version not in materials is skipped",
			infos: []KeyVersionInfo{
				{VersionResourceName: v1Name, IsCurrent: false},
				{VersionResourceName: resourceName + "/cryptoKeyVersions/99", IsCurrent: true},
			},
			want: []crypto.KeyVersion{
				{ID: "key-v1", Rank: 1, IsCurrent: false},
			},
		},
		{
			name: "decrypt error",
			infos: []KeyVersionInfo{
				{VersionResourceName: v1Name, IsCurrent: true},
			},
			failOn:  "enc-v1",
			wantErr: true,
		},
		{
			name: "happy multi-version",
			infos: []KeyVersionInfo{
				{VersionResourceName: v1Name, IsCurrent: false},
				{VersionResourceName: v2Name, IsCurrent: true},
			},
			want: []crypto.KeyVersion{
				{ID: "key-v1", Rank: 1, IsCurrent: false},
				{ID: "key-v2", Rank: 2, IsCurrent: true},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			client := &listingMock{
				mockClient: mockClient{keys: keyMap, failOn: tc.failOn},
				infos:      tc.infos,
				listErr:    tc.listErr,
			}
			fetch := NewPoller(client, resourceName, materials)

			got, err := fetch(context.Background())
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("got %d versions, want %d", len(got), len(tc.want))
			}
			for i := range tc.want {
				if got[i].ID != tc.want[i].ID ||
					got[i].Rank != tc.want[i].Rank ||
					got[i].IsCurrent != tc.want[i].IsCurrent {
					t.Errorf("version[%d] = {ID:%q Rank:%d IsCurrent:%v}, want {ID:%q Rank:%d IsCurrent:%v}",
						i, got[i].ID, got[i].Rank, got[i].IsCurrent,
						tc.want[i].ID, tc.want[i].Rank, tc.want[i].IsCurrent)
				}
				if len(got[i].Bytes) != 32 {
					t.Errorf("version[%d] Bytes len = %d, want 32", i, len(got[i].Bytes))
				}
			}
		})
	}
}
