package crypto_test

import (
	"context"
	"fmt"

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

func ExampleNewProvider_rotation() {
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

	// Rotate: new provider has both keys; current is v2.
	newKey := make([]byte, 32)
	for i := range newKey {
		newKey[i] = byte(i + 100)
	}
	newP, err := crypto.NewProvider(newKey, "key-v2", crypto.WithOldKey(oldKey, "key-v1", 0))
	if err != nil {
		panic(err)
	}
	defer newP.Close()
	newCodec, err := crypto.NewCodec(jsoncodec.New(), newP)
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
