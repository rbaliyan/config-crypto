package crypto_test

import (
	"context"
	"fmt"
	"sync"

	"github.com/rbaliyan/config"
	crypto "github.com/rbaliyan/config-crypto"
	"github.com/rbaliyan/config/codec"
	jsoncodec "github.com/rbaliyan/config/codec/json"
)

func ExampleNewCodec() {
	ctx := context.Background()

	// 32-byte key for AES-256.
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	provider, err := crypto.NewProvider(key, "key-1")
	if err != nil {
		panic(err)
	}
	defer provider.Close()

	encJSON, err := crypto.NewCodec(jsoncodec.New(), provider)
	if err != nil {
		panic(err)
	}
	fmt.Println("Codec name:", encJSON.Name())

	// Decode round-trip.
	data, err := encJSON.Encode(ctx, "my-secret")
	if err != nil {
		panic(err)
	}

	var result string
	if err := encJSON.Decode(ctx, data, &result); err != nil {
		panic(err)
	}
	fmt.Println("Decrypted:", result)

	// Output:
	// Codec name: encrypted:json
	// Decrypted: my-secret
}

func ExampleNewCodec_withConfig() {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	provider, err := crypto.NewProvider(key, "key-1")
	if err != nil {
		panic(err)
	}
	defer provider.Close()

	encJSON, err := crypto.NewCodec(jsoncodec.New(), provider)
	if err != nil {
		panic(err)
	}
	if err := codec.Register(encJSON); err != nil {
		panic(err)
	}

	resolved := codec.Get("encrypted:json")
	fmt.Println("Resolved:", resolved.Name())

	// Output:
	// Resolved: encrypted:json
}

// mapCache is a minimal config.Cache used in examples.
type mapCache struct {
	mu   sync.RWMutex
	data map[string]config.Value
}

func newMapCache() *mapCache { return &mapCache{data: make(map[string]config.Value)} }

func (m *mapCache) Set(_ context.Context, ns, key string, v config.Value) error {
	m.mu.Lock()
	m.data[ns+"/"+key] = v
	m.mu.Unlock()
	return nil
}

func (m *mapCache) Get(_ context.Context, ns, key string) (config.Value, error) {
	m.mu.RLock()
	v, ok := m.data[ns+"/"+key]
	m.mu.RUnlock()
	if !ok {
		return nil, config.ErrNotFound
	}
	return v, nil
}

func (m *mapCache) Delete(_ context.Context, ns, key string) error {
	m.mu.Lock()
	delete(m.data, ns+"/"+key)
	m.mu.Unlock()
	return nil
}

func (m *mapCache) Stats() config.CacheStats { return config.CacheStats{} }

func ExampleNewEncryptedCache() {
	ctx := context.Background()

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	provider, err := crypto.NewProvider(key, "cache-key-v1")
	if err != nil {
		panic(err)
	}
	defer provider.Close()

	inner := newMapCache()
	encCache, err := crypto.NewEncryptedCache(inner, provider)
	if err != nil {
		panic(err)
	}

	// Store an encrypted value.
	val := config.NewValue("my-secret", config.WithValueType(config.TypeString))
	if err := encCache.Set(ctx, "prod", "db/password", val); err != nil {
		panic(err)
	}

	// The inner cache holds ciphertext — not the original string.
	raw, _ := inner.Get(ctx, "prod", "db/password")
	fmt.Println("Inner codec:", raw.Codec())

	// Retrieve and decrypt.
	got, err := encCache.Get(ctx, "prod", "db/password")
	if err != nil {
		panic(err)
	}
	s, _ := got.String()
	fmt.Println("Decrypted:", s)

	// Output:
	// Inner codec: crypto:cache
	// Decrypted: my-secret
}

func ExampleNewKeyRingProvider_rotation() {
	ctx := context.Background()

	oldKey := make([]byte, 32)
	for i := range oldKey {
		oldKey[i] = byte(i)
	}

	// Encrypt with the old key.
	oldP, err := crypto.NewProvider(oldKey, "key-v1")
	if err != nil {
		panic(err)
	}
	defer oldP.Close()
	oldCodec, err := crypto.NewCodec(jsoncodec.New(), oldP)
	if err != nil {
		panic(err)
	}
	encrypted, err := oldCodec.Encode(ctx, "secret-data")
	if err != nil {
		panic(err)
	}

	// Rotate: KeyRingProvider has both keys; current is v2.
	newKey := make([]byte, 32)
	for i := range newKey {
		newKey[i] = byte(i + 100)
	}
	ring, err := crypto.NewKeyRingProvider(newKey, "key-v2", 2)
	if err != nil {
		panic(err)
	}
	defer ring.Close()
	if err := ring.AddKey(oldKey, "key-v1", 1); err != nil {
		panic(err)
	}
	newCodec, err := crypto.NewCodec(jsoncodec.New(), ring)
	if err != nil {
		panic(err)
	}

	var result string
	if err := newCodec.Decode(ctx, encrypted, &result); err != nil {
		panic(err)
	}
	fmt.Println("Decrypted with rotated provider:", result)

	// Output:
	// Decrypted with rotated provider: secret-data
}
