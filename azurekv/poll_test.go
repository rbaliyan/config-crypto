package azurekv

import (
	"context"
	"errors"
	"testing"

	crypto "github.com/rbaliyan/config-crypto"
)

// listingMock implements ListingClient for exercising NewPoller's FetchFn.
// NewPoller calls client.UnwrapKey (from the base Client) per version, so the
// embedded mockClient supplies the unwrap path; failOn drives unwrap failures.
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

	const keyName = "my-key"

	materials := []KeyMaterialEntry{
		{KeyVersion: "v1", Ciphertext: []byte("wrap-v1"), ID: "key-v1", Rank: 1},
		{KeyVersion: "v2", Ciphertext: []byte("wrap-v2"), ID: "key-v2", Rank: 2},
	}
	keyMap := map[string][]byte{
		"wrap-v1": makeKey(1),
		"wrap-v2": makeKey(2),
	}

	cases := []struct {
		name    string
		infos   []KeyVersionInfo
		listErr error
		failOn  string // ciphertext the mock UnwrapKey rejects
		wantErr bool
		want    []crypto.KeyVersion
	}{
		{
			name:    "list error",
			listErr: errors.New("keyvault: forbidden"),
			wantErr: true,
		},
		{
			name: "version not in materials is skipped",
			infos: []KeyVersionInfo{
				{KeyVersion: "v1", IsCurrent: false},
				{KeyVersion: "v-unknown", IsCurrent: true},
			},
			want: []crypto.KeyVersion{
				{ID: "key-v1", Rank: 1, IsCurrent: false},
			},
		},
		{
			name: "unwrap error",
			infos: []KeyVersionInfo{
				{KeyVersion: "v1", IsCurrent: true},
			},
			failOn:  "wrap-v1",
			wantErr: true,
		},
		{
			name: "happy multi-version",
			infos: []KeyVersionInfo{
				{KeyVersion: "v1", IsCurrent: false},
				{KeyVersion: "v2", IsCurrent: true},
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
			fetch := NewPoller(client, keyName, materials)

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
