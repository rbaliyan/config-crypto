package rotation

import (
	"context"
	"errors"
	"testing"
	"time"

	crypto "github.com/rbaliyan/config-crypto"
	"github.com/rbaliyan/config/codec"
	_ "github.com/rbaliyan/config/codec/json"
	"github.com/rbaliyan/config/memory"
)

func mustKey(t *testing.T) []byte {
	t.Helper()
	return []byte("0123456789abcdef0123456789abcdef")
}

func mustRotatingCodec(t *testing.T) (crypto.KeyRingProvider, *crypto.Codec) {
	t.Helper()
	ring, err := crypto.NewKeyRingProvider(mustKey(t), "v1", 1)
	if err != nil {
		t.Fatalf("NewKeyRingProvider: %v", err)
	}
	inner := codec.Get("json")
	if inner == nil {
		t.Fatal("json codec not registered")
	}
	c, err := crypto.NewCodec(inner, ring)
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}
	return ring, c
}

func TestNewOrchestrator_NilArgs(t *testing.T) {
	ring, c := mustRotatingCodec(t)
	store := memory.NewStore()

	if _, err := NewOrchestrator(nil, store, c); err == nil {
		t.Fatal("expected error for nil ring")
	}
	if _, err := NewOrchestrator(ring, nil, c); err == nil {
		t.Fatal("expected error for nil store")
	}
	if _, err := NewOrchestrator(ring, store, nil); err == nil {
		t.Fatal("expected error for nil codec")
	}
}

func TestOrchestrator_StartRequiresNamespaces(t *testing.T) {
	ring, c := mustRotatingCodec(t)
	store := memory.NewStore()

	o, err := NewOrchestrator(ring, store, c)
	if err != nil {
		t.Fatalf("NewOrchestrator: %v", err)
	}
	if _, err := o.Start(context.Background()); err == nil {
		t.Fatal("expected error when no namespaces configured")
	}
}

func TestOrchestrator_StartOnce(t *testing.T) {
	ring, c := mustRotatingCodec(t)
	store := memory.NewStore()

	o, err := NewOrchestrator(ring, store, c, WithNamespaces("ns1"), WithScanInterval(time.Hour))
	if err != nil {
		t.Fatalf("NewOrchestrator: %v", err)
	}
	stop, err := o.Start(context.Background())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer stop()

	if _, err := o.Start(context.Background()); err == nil {
		t.Fatal("expected second Start to fail")
	}
}

func TestOrchestrator_StopIsIdempotent(t *testing.T) {
	ring, c := mustRotatingCodec(t)
	store := memory.NewStore()

	o, err := NewOrchestrator(ring, store, c, WithNamespaces("ns1"), WithScanInterval(time.Hour))
	if err != nil {
		t.Fatalf("NewOrchestrator: %v", err)
	}
	stop, err := o.Start(context.Background())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	stop()
	stop() // must not panic or hang
}

func TestOrchestrator_ReencryptNamespace_NoStaleKeys(t *testing.T) {
	ring, c := mustRotatingCodec(t)

	store := memory.NewStore()
	if err := store.Connect(context.Background()); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer store.Close(context.Background())

	o, err := NewOrchestrator(ring, store, c, WithNamespaces("ns1"))
	if err != nil {
		t.Fatalf("NewOrchestrator: %v", err)
	}
	// empty namespace, no rotation work to do
	count, err := o.ReencryptNamespace(context.Background(), "ns1")
	if err != nil {
		t.Fatalf("ReencryptNamespace: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected 0 re-encryptions, got %d", count)
	}
}

func TestOrchestrator_ReportErrUsesConfiguredHandler(t *testing.T) {
	ring, c := mustRotatingCodec(t)
	store := memory.NewStore()

	var got error
	o, err := NewOrchestrator(ring, store, c,
		WithNamespaces("ns1"),
		WithErrorHandler(func(namespace, key string, err error) { got = err }),
	)
	if err != nil {
		t.Fatalf("NewOrchestrator: %v", err)
	}
	o.reportErr("ns1", "k1", errors.New("boom"))
	if got == nil || got.Error() != "boom" {
		t.Fatalf("expected handler to receive err, got %v", got)
	}
}
