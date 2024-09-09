// Package db contains the database for homeauth.
package db

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"sync/atomic"

	"github.com/andrew-d/homeauth/internal/migrate"
)

// DB is the main database interface.
type DB struct {
	sql    *SQLiteDB
	closed atomic.Bool
	log    *slog.Logger
}

// NewDB creates a new DB.
func NewDB(log *slog.Logger, path string) (*DB, error) {
	if log == nil {
		log = slog.Default()
	}
	ctx := context.Background()
	sqlDB, err := NewSQLiteDB(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}

	// Attempt to apply migrations to the table.
	runner := migrate.NewRunner(
		migrations,
		func(ctx context.Context) (migrate.RunnerTx, error) {
			return sqlDB.sql.BeginTx(ctx, nil)
		},
		func(ctx context.Context, tx migrate.LimitedTx) (int, error) {
			var version int
			if err := tx.QueryRowContext(ctx, `PRAGMA user_version;`).Scan(&version); err != nil {
				return 0, err
			}
			return version, nil
		},
		func(ctx context.Context, tx migrate.LimitedTx, version int) error {
			// Slightly annoyingly, we can't use the ? placeholder
			// for the version here because PRAGMAs don't support
			// parameters. This is fine since it's just an integer,
			// but don't copy this :)
			sql := fmt.Sprintf(`PRAGMA user_version = %d;`, version)
			_, err := tx.ExecContext(ctx, sql, version)
			return err
		},
	)
	if err := runner.Migrate(ctx); err != nil {
		return nil, fmt.Errorf("applying migrations: %w", err)
	}

	db := &DB{
		sql: sqlDB,
		log: log,
	}
	return db, nil
}

// Close closes the database.
func (db *DB) Close() error {
	if db.closed.CompareAndSwap(false, true) {
		return db.sql.Close()
	}
	return nil
}

// Tx is a wrapper around a SQL transaction that we can attach additional
// helper methods to.
type Tx struct {
	*sql.Tx
}

// ReadTx starts a new write transaction.
func (db *DB) ReadTx(ctx context.Context) (*Tx, error) {
	tx, err := db.sql.BeginReadTx(ctx)
	if err != nil {
		return nil, fmt.Errorf("starting transaction: %w", err)
	}
	return &Tx{tx}, nil
}

// Tx starts a new write transaction.
func (db *DB) Tx(ctx context.Context) (*Tx, error) {
	tx, err := db.sql.BeginWriteTx(ctx)
	if err != nil {
		return nil, fmt.Errorf("starting transaction: %w", err)
	}
	return &Tx{tx}, nil
}

// MustTx starts a new write transaction, panicking on error.
func (db *DB) MustTx(ctx context.Context) *Tx {
	tx, err := db.Tx(ctx)
	if err != nil {
		panic(err)
	}
	return tx
}

// MustReadTx starts a new read transaction, panicking on error.
func (db *DB) MustReadTx(ctx context.Context) *Tx {
	tx, err := db.ReadTx(ctx)
	if err != nil {
		panic(err)
	}
	return tx
}
