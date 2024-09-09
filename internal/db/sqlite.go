package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"runtime"

	"modernc.org/sqlite"
)

// SQLiteDB is a wrapper around a SQLite database that segments the read-only
// and read-write connections into separate connection pools.
type SQLiteDB struct {
	sql   *sql.DB
	sqlRO *sql.DB
}

func NewSQLiteDB(ctx context.Context, path string) (*SQLiteDB, error) {
	// Open the read-write connection.
	db, err := openDB(ctx, "file:"+path, 2)
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}

	// Open the read-only connection.
	numROConns := max(runtime.GOMAXPROCS(0)-1, 1)
	dbRO, err := openDB(ctx, "file:"+path+"?mode=ro", numROConns)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("opening read-only database: %w", err)
	}

	return &SQLiteDB{
		sql:   db,
		sqlRO: dbRO,
	}, nil
}

// Close closes the database.
func (db *SQLiteDB) Close() error {
	// Close all read transactions first so that we can truncate the WAL.
	err1 := db.sqlRO.Close()

	// Best-effort attempt to truncate the WAL.
	db.sql.Exec("PRAGMA wal_checkpoint(FULL);")

	err2 := db.sql.Close()
	return errors.Join(err1, err2)
}

// BeginTx will create and return a new transaction.
func (db *SQLiteDB) BeginTx(ctx context.Context, opts *sql.TxOptions) (*sql.Tx, error) {
	if opts != nil && opts.ReadOnly {
		return db.sqlRO.BeginTx(ctx, opts)
	}
	return db.sql.BeginTx(ctx, opts)
}

// BeginWriteTx is a helper function to create a write transaction.
func (db *SQLiteDB) BeginWriteTx(ctx context.Context) (*sql.Tx, error) {
	return db.sql.BeginTx(ctx, nil)
}

// BeginReadTx is a helper function to create a read transaction.
func (db *SQLiteDB) BeginReadTx(ctx context.Context) (*sql.Tx, error) {
	return db.sqlRO.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
}

// openDB is the shared code for opening a connection to a SQLite database.
func openDB(ctx context.Context, sqliteURI string, numConns int, extraInit ...string) (_ *sql.DB, retErr error) {
	db, err := sql.Open("sqlite", sqliteURI)
	if err != nil {
		return nil, fmt.Errorf("opening SQLite database: %w", err)
	}

	defer func() {
		if retErr != nil {
			db.Close()
		}
	}()

	// Configure each new connection as it's opened.
	driver := db.Driver().(*sqlite.Driver)
	driver.RegisterConnectionHook(func(conn sqlite.ExecQuerierContext, dsn string) error {
		// Configure the connection with pragmas; note that order matters here.
		for _, stmt := range []string{
			`PRAGMA busy_timeout=10000;`,
			`PRAGMA journal_mode=WAL;`,
			`PRAGMA synchronous=NORMAL;`,
			`PRAGMA auto_vacuum=INCREMENTAL;`,
		} {
			if _, err := conn.ExecContext(ctx, stmt, nil); err != nil {
				return fmt.Errorf("executing pragma %q: %w", stmt, err)
			}
		}

		// Perform any extra initialization.
		for _, init := range extraInit {
			if _, err := conn.ExecContext(ctx, init, nil); err != nil {
				return fmt.Errorf("executing extra init: %w", err)
			}
		}
		return nil
	})

	// Tell the database/sql driver to never expire connections; we want a
	// stable connpool that doesn't close connections on us.
	numConns = max(numConns, 2)
	db.SetMaxOpenConns(numConns)
	db.SetMaxIdleConns(numConns)
	db.SetConnMaxLifetime(0)
	db.SetConnMaxIdleTime(0)

	// Open a number of connections equal to the number of connections we
	// want, to fill the connpool, and then close them all so that our
	// caller can use them.
	var conns []*sql.Conn
	for i := 0; i < numConns; i++ {
		conn, err := db.Conn(ctx)
		if err != nil {
			return nil, fmt.Errorf("opening a connection: %w", err)
		}
		conns = append(conns, conn)
	}
	for _, conn := range conns {
		conn.Close()
	}

	return db, nil
}
