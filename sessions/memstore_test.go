package sessions

import (
	"context"
	"errors"
	"testing"
	"time"
)

func testStore[T any](t *testing.T, store Store[T], setTime func(time.Time)) {
	var zero T

	// Set the time to a fixed value.
	now := time.Unix(1729223000, 0)
	setTime(now)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const token = "token"

	// Store a session.
	if err := store.Commit(ctx, token, &zero, now.Add(time.Hour)); err != nil {
		t.Fatalf("store.Commit failed: %v", err)
	}

	// Verify we can get the session.
	var out T
	if err := store.Find(ctx, token, &out); err != nil {
		t.Logf("store: %#v", store)
		t.Fatalf("store.Find failed: %v", err)
	}

	// Verify that we see it in the List output.
	sessions, err := store.List(ctx)
	if err != nil {
		t.Fatalf("store.List failed: %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("expected one session, got %d", len(sessions))
	}
	if _, ok := sessions[token]; !ok {
		t.Fatalf("expected %q in sessions, got %v", token, sessions)
	}

	// Delete the session.
	if err := store.Delete(ctx, token); err != nil {
		t.Fatalf("store.Delete failed: %v", err)
	}

	// Verify that it's gone.
	err = store.Find(ctx, token, &out)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
	sessions, err = store.List(ctx)
	if err != nil {
		t.Fatalf("store.List failed: %v", err)
	}
	if len(sessions) != 0 {
		t.Fatalf("expected zero sessions, got %d", len(sessions))
	}

	// Verify that deleting it again isn't an error.
	if err := store.Delete(ctx, token); err != nil {
		t.Fatalf("store.Delete failed: %v", err)
	}

	t.Run("Expiry", func(t *testing.T) {
		const token = "token-with-expiry"

		// Insert a session with a short expiry.
		expiry := now.Add(time.Second)
		if err := store.Commit(ctx, token, &zero, expiry); err != nil {
			t.Fatalf("store.Commit failed: %v", err)
		}

		// Move past the expiry.
		setTime(expiry.Add(time.Second))

		// Verify that the session is gone.
		err = store.Find(ctx, token, &out)
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("expected ErrNotFound, got %v", err)
		}

		// Verify that it's gone from List.
		sessions, err := store.List(ctx)
		if err != nil {
			t.Fatalf("store.List failed: %v", err)
		}
		if len(sessions) != 0 {
			t.Fatalf("expected zero sessions, got %d", len(sessions))
		}
	})
}

func TestMemStore(t *testing.T) {
	now := new(time.Time)
	store := NewMemStore[int]()
	store.timeNow = func() time.Time {
		return *now
	}
	testStore(t, store, func(tm time.Time) {
		*now = tm
	})
}

func TestMemStore_CleanExpired(t *testing.T) {
	now := new(time.Time)
	store := NewMemStore[int]()
	store.timeNow = func() time.Time {
		return *now
	}
	*now = time.Unix(1729223000, 0)
	ctx := context.Background()

	// Insert a session with a short expiry.
	const token = "token"
	val := new(int)
	if err := store.Commit(ctx, token, val, now.Add(time.Hour)); err != nil {
		t.Fatalf("store.Commit failed: %v", err)
	}

	// Insert a session with a long expiry.
	const longToken = "long-token"
	longVal := new(int)
	*longVal = 1
	if err := store.Commit(ctx, longToken, longVal, now.Add(time.Hour*24)); err != nil {
		t.Fatalf("store.Commit failed: %v", err)
	}

	// Move past the expiry time.
	*now = now.Add(time.Hour).Add(time.Second)

	// Verify that the session is gone.
	var out int
	err := store.Find(ctx, token, &out)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}

	// Verify that the long-expiry session is still there.
	if err := store.Find(ctx, longToken, &out); err != nil {
		t.Fatalf("store.Find failed: %v", err)
	}

	// The expired session should still be in our store...
	store.mu.RLock()
	sessionsInStore := len(store.sessions)
	store.mu.RUnlock()
	if sessionsInStore != 2 {
		t.Fatalf("expected two sessions in store, got %d", sessionsInStore)
	}

	// ... until we call CleanExpired
	store.CleanExpired()
	store.mu.RLock()
	sessionsInStore = len(store.sessions)
	store.mu.RUnlock()
	if sessionsInStore != 1 {
		t.Fatalf("expected 1 session in store, got %d", sessionsInStore)
	}

	// The long-expiry session should still be there after we clean.
	if err := store.Find(ctx, longToken, &out); err != nil {
		t.Fatalf("store.Find failed: %v", err)
	}
}
