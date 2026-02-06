package crypto_test

import (
	"fmt"

	crypto "github.com/rbaliyan/config-crypto"
	"github.com/rbaliyan/config/codec"
)

func ExampleNewCodec() {
	// Create a 32-byte key for AES-256
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	provider, err := crypto.NewStaticKeyProvider(key, "key-1")
	if err != nil {
		panic(err)
	}

	// Wrap the JSON codec with encryption
	encJSON := crypto.NewCodec(codec.JSON(), provider)
	fmt.Println("Codec name:", encJSON.Name())

	// Encode encrypts the JSON-serialized value
	data, err := encJSON.Encode("my-secret")
	if err != nil {
		panic(err)
	}
	fmt.Printf("Encrypted size: %d bytes\n", len(data))

	// Decode decrypts and deserializes
	var result string
	if err := encJSON.Decode(data, &result); err != nil {
		panic(err)
	}
	fmt.Println("Decrypted:", result)

	// Output:
	// Codec name: encrypted:json
	// Encrypted size: 109 bytes
	// Decrypted: my-secret
}

func ExampleNewCodec_withConfig() {
	// Create a key
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	provider, err := crypto.NewStaticKeyProvider(key, "key-1")
	if err != nil {
		panic(err)
	}

	// Create and register the encrypted codec
	encJSON := crypto.NewCodec(codec.JSON(), provider)
	codec.Register(encJSON)

	// Now "encrypted:json" is available in the codec registry
	resolved := codec.Get("encrypted:json")
	fmt.Println("Resolved:", resolved.Name())

	// Output:
	// Resolved: encrypted:json
}

func ExampleNewStaticKeyProvider_rotation() {
	// Original key
	oldKey := make([]byte, 32)
	for i := range oldKey {
		oldKey[i] = byte(i)
	}

	// Encrypt with original key
	oldProvider, err := crypto.NewStaticKeyProvider(oldKey, "key-v1")
	if err != nil {
		panic(err)
	}
	oldCodec := crypto.NewCodec(codec.JSON(), oldProvider)

	encrypted, err := oldCodec.Encode("secret-data")
	if err != nil {
		panic(err)
	}

	// Rotate: new key is current, old key available for decryption
	newKey := make([]byte, 32)
	for i := range newKey {
		newKey[i] = byte(i + 100)
	}

	newProvider, err := crypto.NewStaticKeyProvider(newKey, "key-v2",
		crypto.WithOldKey(oldKey, "key-v1"),
	)
	if err != nil {
		panic(err)
	}
	newCodec := crypto.NewCodec(codec.JSON(), newProvider)

	// Can decrypt data encrypted with old key
	var result string
	if err := newCodec.Decode(encrypted, &result); err != nil {
		panic(err)
	}
	fmt.Println("Decrypted with rotated provider:", result)

	// New encryptions use the new key
	reEncrypted, err := newCodec.Encode(result)
	if err != nil {
		panic(err)
	}

	var result2 string
	if err := newCodec.Decode(reEncrypted, &result2); err != nil {
		panic(err)
	}
	fmt.Println("Re-encrypted and decrypted:", result2)

	// Output:
	// Decrypted with rotated provider: secret-data
	// Re-encrypted and decrypted: secret-data
}
