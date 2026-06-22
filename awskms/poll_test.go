package awskms

import (
	"context"
	"errors"
	"fmt"
	"testing"

	crypto "github.com/rbaliyan/config-crypto"
)

// listingMock implements ListingClient for exercising NewPoller's FetchFn.
type listingMock struct {
	mockClient                   // embeds Decrypt for the base Client contract
	infos       []KeyVersionInfo // returned by ListKeyVersions
	listErr     error            // if set, ListKeyVersions fails
	decryptFail string           // version ID whose DecryptVersion call fails
}

func (m *listingMock) ListKeyVersions(_ context.Context, _ string) ([]KeyVersionInfo, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	return m.infos, nil
}

func (m *listingMock) DecryptVersion(_ context.Context, _, versionID string, ciphertext []byte) ([]byte, error) {
	if versionID == m.decryptFail {
		return nil, fmt.Errorf("kms: decrypt version %q denied", versionID)
	}
	plaintext, ok := m.keys[string(ciphertext)]
	if !ok {
		return nil, fmt.Errorf("kms: invalid ciphertext for version %q", versionID)
	}
	return plaintext, nil
}

func TestNewPoller_FetchFn(t *testing.T) {
	t.Parallel()

	const kmsKeyID = "arn:aws:kms:us-east-1:123:key/abc"

	materials := []KeyMaterialEntry{
		{VersionID: "v1", Ciphertext: []byte("enc-v1"), ID: "key-v1", Rank: 1},
		{VersionID: "v2", Ciphertext: []byte("enc-v2"), ID: "key-v2", Rank: 2},
	}
	keyMap := map[string][]byte{
		"enc-v1": makeKey(1),
		"enc-v2": makeKey(2),
	}

	cases := []struct {
		name        string
		infos       []KeyVersionInfo
		listErr     error
		decryptFail string
		wantErr     bool
		want        []crypto.KeyVersion // only ID/Rank/IsCurrent asserted
	}{
		{
			name:    "list error",
			listErr: errors.New("kms: throttled"),
			wantErr: true,
		},
		{
			name: "version not in materials is skipped",
			infos: []KeyVersionInfo{
				{VersionID: "v1", IsCurrent: false},
				{VersionID: "v-unknown", IsCurrent: true},
			},
			want: []crypto.KeyVersion{
				{ID: "key-v1", Rank: 1, IsCurrent: false},
			},
		},
		{
			name: "decrypt error",
			infos: []KeyVersionInfo{
				{VersionID: "v1", IsCurrent: true},
			},
			decryptFail: "v1",
			wantErr:     true,
		},
		{
			name: "happy multi-version",
			infos: []KeyVersionInfo{
				{VersionID: "v1", IsCurrent: false},
				{VersionID: "v2", IsCurrent: true},
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
				mockClient:  mockClient{keys: keyMap},
				infos:       tc.infos,
				listErr:     tc.listErr,
				decryptFail: tc.decryptFail,
			}
			fetch := NewPoller(client, kmsKeyID, materials)

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
