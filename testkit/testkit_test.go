package testkit

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	secrets "github.com/goliatone/ctx/pkg/go-secrets"
)

func TestFakesAreDeterministicAndConcurrent(t *testing.T) {
	repo := NewRepository()
	now := time.Unix(10, 0)
	ref, _ := secrets.ParseReference("env://TOKEN")
	for _, id := range []string{"b", "a"} {
		set := secrets.ReferenceSet{ID: id, Name: id, Purpose: "test", Scope: secrets.Scope{Kind: "host", ID: "h"}, Candidates: []secrets.Candidate{{Reference: ref, Enabled: true}}, Status: secrets.ReferenceSetActive, Revision: 1, CreatedAt: now, UpdatedAt: now}
		if err := repo.Create(context.Background(), set); err != nil {
			t.Fatal(err)
		}
	}
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() { ; _, _ = repo.List(context.Background()) })
	}
	wg.Wait()
	sets, _ := repo.List(context.Background())
	if sets[0].ID != "a" {
		t.Fatalf("ordering: %#v", sets)
	}
	p := NewProvider("fake", "env")
	p.SetValue([]byte("canary"))
	value, err := p.Resolve(context.Background(), ref)
	if err != nil {
		t.Fatal(err)
	}
	if value.String() == "canary" {
		t.Fatal("secret leaked")
	}
	value.Destroy()
}

func TestProviderConfigurationIsConcurrentAndBounded(t *testing.T) {
	provider := NewProvider("fake", "env")
	provider.SetValue([]byte("canary"))
	provider.SetMaxBytes(3)
	ref, _ := secrets.ParseReference("env://TOKEN")
	if _, err := provider.Resolve(context.Background(), ref); !secrets.IsKind(err, secrets.ErrorInvalidSecret) {
		t.Fatalf("output bound: %v", err)
	}
	provider.SetMaxBytes(64)
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			provider.SetValue([]byte("rotated"))
			provider.SetErrorKind(secrets.ErrorTemporary)
		}()
		go func() {
			defer wg.Done()
			value, _ := provider.Resolve(context.Background(), ref)
			if value != nil {
				value.Destroy()
			}
		}()
	}
	wg.Wait()
	provider.SetWaitForCancellation(true)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := provider.Resolve(ctx, ref); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation: %v", err)
	}
}
