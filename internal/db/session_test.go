package db

import (
	"context"
	"maps"
	"reflect"
	"testing"
	"time"
)

func TestSession(t *testing.T) {
	db := newTestDB(t)

	ctx := context.Background()

	expiry := time.Now().Add(time.Hour).Truncate(time.Millisecond)
	sess := &Session{
		ID:     "123",
		Expiry: expiry,
		UserID: 42,
		Data:   map[string]any{"foo": "bar"},
	}

	// Put the session then get it back
	tx := db.MustTx(ctx)
	defer tx.Rollback()

	if err := tx.PutSession(ctx, sess); err != nil {
		t.Fatal(err)
	}
	got, err := tx.GetSessionByID(ctx, sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, sess) {
		t.Fatalf("got %+v, want %+v", got, sess)
	}

	// Verify that if we change something, put it, and then read it back,
	// it updates.
	expiry = expiry.Add(time.Hour)
	sess.Expiry = expiry
	sess.Data["baz"] = "asdf"

	if err := tx.PutSession(ctx, sess); err != nil {
		t.Fatal(err)
	}
	got, err = tx.GetSessionByID(ctx, sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, sess) {
		t.Fatalf("got %+v, want %+v", got, sess)
	}

	// However, updating a session with a different user ID should be a
	// no-op (and neither update the user ID nor any other fields.
	newSess := &Session{
		ID:     sess.ID,
		Expiry: expiry.Add(time.Hour),
		UserID: sess.UserID + 1,
		Data:   maps.Clone(sess.Data),
	}
	newSess.Data["bbbb"] = "cccc"

	if err := tx.PutSession(ctx, newSess); err != nil {
		t.Fatal(err)
	}
	got, err = tx.GetSessionByID(ctx, newSess.ID)
	if err != nil {
		t.Fatal(err)
	}

	// We expect to get back the old session, not the new one.
	if !reflect.DeepEqual(got, sess) {
		t.Fatalf("got %+v, want %+v", got, sess)
	}
}
