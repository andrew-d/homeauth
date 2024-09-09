package db

import (
	"context"
	"path/filepath"
	"testing"
)

func TestDB(t *testing.T) {
	tdir := t.TempDir()
	db, err := NewDB(nil, filepath.Join(tdir, "test.db"))
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}

	// Test using a basic query that does some simple addition, to verify
	// that the database works.
	tx, err := db.ReadTx(context.Background())
	if err != nil {
		t.Fatalf("ReadTx: %v", err)
	}
	defer tx.Rollback()

	var sum int
	if err := tx.QueryRow("SELECT 1 + 1").Scan(&sum); err != nil {
		t.Fatalf("QueryRow: %v", err)
	}
	if sum != 2 {
		t.Errorf("sum = %d; want 2", sum)
	}

	if err := db.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

func newTestDB(tb testing.TB) *DB {
	tb.Helper()

	tdir := tb.TempDir()
	db, err := NewDB(nil, filepath.Join(tdir, "test.db"))
	if err != nil {
		tb.Fatalf("NewDB: %v", err)
	}
	return db
}
