package rotation

import (
	"context"
	"testing"

	crypto "github.com/rbaliyan/config-crypto"
	"github.com/rbaliyan/config/codec"
	"github.com/rbaliyan/config/memory"

	config "github.com/rbaliyan/config"
)

// TestOrchestrator_NamespaceBlindCodec_Characterization documents a design
// limitation flagged in review: the Orchestrator is constructed with a single,
// namespace-blind *crypto.Codec (see NewOrchestrator's signature). It cannot be
// given a per-namespace crypto.SelectorCodec — that is a distinct type and does
// not satisfy the *crypto.Codec parameter, so the mismatch is caught at compile
// time rather than producing wrong ciphertext at runtime.
//
// The consequence: if an operator routes different namespaces to different KEKs
// via a SelectorCodec at write time, but then wires the Orchestrator with a
// *crypto.Codec built on the provider for only ONE of those namespaces, the
// sweep will attempt to decrypt values from the OTHER namespaces with the wrong
// KEK. This test characterises that behaviour: such values cannot be decrypted,
// the per-value error path fires, and they are NOT silently corrupted (the
// failed Reverse aborts before any Set).
//
// This is current, intended behaviour given the type constraint; it is captured
// here so a future change to accept SelectorCodec is a conscious decision.
func TestOrchestrator_NamespaceBlindCodec_Characterization(t *testing.T) {
	ctx := context.Background()

	inner := codec.Get("json")
	if inner == nil {
		t.Fatal("json codec not registered")
	}

	// Two namespaces, two independent KEK rings.
	ringA, err := crypto.NewKeyRingProvider([]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), "a-v1", 1)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ringA.Close() })
	ringB, err := crypto.NewKeyRingProvider([]byte("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"), "b-v1", 1)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ringB.Close() })

	codecA, err := crypto.NewCodec(inner, ringA)
	if err != nil {
		t.Fatal(err)
	}
	codecB, err := crypto.NewCodec(inner, ringB)
	if err != nil {
		t.Fatal(err)
	}

	store := memory.NewStore()
	if err := store.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close(ctx) })

	// Seed namespace "tenant-b" with values encrypted under ring B.
	const ns = "tenant-b"
	ctB, err := codecB.Encode(ctx, "b-secret")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Set(ctx, ns, "k1", config.NewRawValue(ctB, codecB.Name())); err != nil {
		t.Fatal(err)
	}

	// Rotate ring B so the value is stale (a real sweep would target it).
	if err := ringB.AddKey([]byte("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBC"), "b-v2", 2); err != nil {
		t.Fatal(err)
	}
	if err := ringB.SetCurrentKey("b-v2"); err != nil {
		t.Fatal(err)
	}

	// Misconfiguration: orchestrator wired with codec A (ring A) but scanning a
	// namespace whose values were written under ring B. The orchestrator uses
	// ringB only for the NeedsReencryption staleness check here to surface the
	// stale value; re-encryption goes through codecA, which holds the wrong KEK.
	var reportedErr error
	o, err := NewOrchestrator(ringB, store, codecA,
		WithNamespaces(ns),
		WithErrorHandler(func(_, _ string, err error) { reportedErr = err }),
	)
	if err != nil {
		t.Fatalf("NewOrchestrator: %v", err)
	}

	count, err := o.ReencryptNamespace(ctx, ns)
	if err != nil {
		t.Fatalf("ReencryptNamespace returned namespace-level error: %v", err)
	}

	// Characterised behaviour: the wrong-KEK decrypt fails, so nothing is
	// re-encrypted and the per-value error handler is invoked.
	if count != 0 {
		t.Errorf("count = %d, want 0 (cross-KEK decrypt must not succeed)", count)
	}
	if reportedErr == nil {
		t.Error("expected the per-value error handler to receive a decrypt failure")
	}

	// And the original value is untouched: still decryptable with codec B.
	v, err := store.Get(ctx, ns, "k1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	raw, _ := v.Marshal(ctx)
	var got string
	if err := codecB.Decode(ctx, raw, &got); err != nil {
		t.Fatalf("original value was corrupted by the failed sweep: %v", err)
	}
	if got != "b-secret" {
		t.Errorf("original value changed: got %q, want %q", got, "b-secret")
	}
}
