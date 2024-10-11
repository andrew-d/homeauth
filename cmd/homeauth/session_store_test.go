package main

import (
	"bytes"
	"path/filepath"
	"testing"
	"time"

	"github.com/andrew-d/homeauth/internal/jsonfile"
)

func TestSessionStore(t *testing.T) {
	now := time.Unix(1728846882, 0)
	timeNow := func() time.Time {
		return now
	}

	tdir := t.TempDir()
	database, err := jsonfile.New[data](filepath.Join(tdir, "data.json"))
	if err != nil {
		t.Fatalf("failed to create database: %v", err)
	}
	store := &jsonFileStore{
		db:      database,
		timeNow: timeNow,
	}

	// Insert an item into the store
	err = store.Commit("token", []byte("contents"), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("failed to commit: %v", err)
	}

	// Advance by less than an hour and verify it's still in the store.
	now = now.Add(time.Hour - 1)
	if err := store.Cleanup(); err != nil {
		t.Fatalf("failed to cleanup: %v", err)
	}

	b, found, err := store.Find("token")
	if err != nil {
		t.Fatalf("failed to find: %v", err)
	}
	if !found {
		t.Fatalf("expected to find token")
	}
	if !bytes.Equal(b, []byte("contents")) {
		t.Fatalf("expected token contents to be 'contents', got %q", b)
	}

	// Now advance past the hour mark and verify that it's both not
	// returned pre-clean (i.e. the invariant doesn't depend on calling
	// Cleanup at the right time), and post-clean.
	now = now.Add(2)
	_, found, err = store.Find("token")
	if err != nil {
		t.Fatalf("failed to find: %v", err)
	}
	if found {
		t.Fatalf("expected not to find token")
	}

	if err := store.Cleanup(); err != nil {
		t.Fatalf("failed to cleanup: %v", err)
	}
	_, found, err = store.Find("token")
	if err != nil {
		t.Fatalf("failed to find: %v", err)
	}
	if found {
		t.Fatalf("expected not to find token")
	}

	// Verify that there's no sessions in the store.
	database.Read(func(d *data) {
		if len(d.Sessions) != 0 {
			t.Errorf("expected no sessions in store, got %d", len(d.Sessions))
		}
	})
}
