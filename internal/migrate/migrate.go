package migrate

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"
)

// Migration is the interface for a migration, which is responsible for
// updating the database schema by a single version.
//
// Note that a migration should not call Commit or Rollback on the Tx; that
// will be done by the migration runner.
type Migration interface {
	Migrate(context.Context, LimitedTx) error
}

// MigrationFunc is a function that implements the Migration interface.
type MigrationFunc func(context.Context, LimitedTx) error

func (f MigrationFunc) Migrate(ctx context.Context, tx LimitedTx) error {
	return f(ctx, tx)
}

// MigrationSQL is a migration that runs a single SQL statement using the
// ExecContext function.
type MigrationSQL string

func (m MigrationSQL) Migrate(ctx context.Context, tx LimitedTx) error {
	ss := string(m)
	if strings.Contains(ss, "CREATE TABLE ") {
		// Clean up the SQL statement to make it look nicer.
		ss = cleanCreateTableSQL(ss)
	}

	_, err := tx.ExecContext(ctx, ss)
	return err
}

// LimitedTx is a limited subset of the database/sql.Tx interface, which is
// used by migrations.
type LimitedTx interface {
	Exec(string, ...any) (sql.Result, error)
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	Prepare(string) (*sql.Stmt, error)
	PrepareContext(context.Context, string) (*sql.Stmt, error)
	Query(string, ...any) (*sql.Rows, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRow(string, ...any) *sql.Row
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// RunnerTx is the subset of the database/sql.Tx interface that the migration
// Runner needs.
type RunnerTx interface {
	LimitedTx

	Commit() error
	Rollback() error
}

// GetVersionFunc is a function that returns the current schema version of a
// database.
type GetVersionFunc func(context.Context, LimitedTx) (int, error)

// SetVersionFunc is a function that sets the schema version of a database.
type SetVersionFunc func(context.Context, LimitedTx, int) error

// Runner is responsible for running migrations.
type Runner struct {
	migrations []Migration
	getTx      func(context.Context) (RunnerTx, error)
	getVersion GetVersionFunc
	setVersion SetVersionFunc
}

// NewRunner creates a new migration runner, using the provided hook functions
// to obtain a transaction and to update the version.
func NewRunner(
	migrations []Migration,
	getTx func(context.Context) (RunnerTx, error),
	getVersion GetVersionFunc,
	setVersion SetVersionFunc,
) *Runner {
	return &Runner{
		migrations: migrations,
		getTx:      getTx,
		getVersion: getVersion,
		setVersion: setVersion,
	}
}

// Migrate runs all migrations.
func (r *Runner) Migrate(ctx context.Context) (retErr error) {
	// We do everything in a single transaction.
	tx, err := r.getTx(ctx)
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer func() {
		if retErr != nil {
			tx.Rollback()
		}
	}()

	// Start by fetching the version in the database.
	version, err := r.getVersion(ctx, tx)
	if err != nil {
		return fmt.Errorf("getting database version: %w", err)
	}

	// The version we're migrating to is the length of the migrations
	// slice.
	targetVersion := len(r.migrations)

	// Ensure that we don't migrate if we're past the target version already.
	if version == targetVersion {
		// Nothing to do
		return nil
	}

	if version > targetVersion {
		return fmt.Errorf("database version (%d) is newer than the target version (%d)", version, targetVersion)
	}

	// Apply each version in turn.
	for i := version; i < targetVersion; i++ {
		if err := r.migrations[i].Migrate(ctx, tx); err != nil {
			if err2 := tx.Rollback(); err2 != nil {
				return fmt.Errorf("when migrating from %d to %d, migration failed and rollback failed (rollback: %v): %w", i, i+1, err2, err)
			}
			return fmt.Errorf("when migrating from %d to %d: %w", i, i+1, err)
		}
	}

	// Now, update the version in the database.
	if err := r.setVersion(ctx, tx, targetVersion); err != nil {
		if err2 := tx.Rollback(); err2 != nil {
			return fmt.Errorf("setting migration version failed and rollback failed (rollback: %v): %w", err2, err)
		}
		return fmt.Errorf("setting migration version: %w", err)
	}

	// And commit
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing transaction: %w", err)
	}

	return nil
}

// cleanCreateTableSQL is a helper function to clean up a CREATE TABLE SQL
// statement, since SQLite stores the SQL exactly as entered in the database.
//
// TODO(andrew-d): maybe use https://github.com/lithammer/dedent ?
func cleanCreateTableSQL(origSQL string) string {
	// First, clean up tabs and extra whitespace.
	sql := strings.ReplaceAll(origSQL, "\t", "    ")
	sql = strings.TrimSpace(sql)
	lines := strings.Split(sql, "\n")

	if len(lines) == 1 {
		return sql
	}

	// Starting from the second line, see if all lines have a common prefix of whitespace.
	// We can do this by slicing off everything including and after the
	// first non-whitespace character, which gives us a list of all
	// whitespace prefixes. Then, sort them by length.
	var prefixes []string
	for _, line := range lines[1:] {
		// Find the first non-whitespace character. If a line is all
		// whitespace, ignore it since we will replace it with a blank
		// line.
		for i, chr := range line {
			if chr != ' ' {
				prefixes = append(prefixes, line[:i])
				break
			}
		}
	}

	// Sort by length
	sort.Slice(prefixes, func(i, j int) bool {
		return len(prefixes[i]) < len(prefixes[j])
	})

	// Now, we know that the first prefix is the common prefix. We can
	// remove it.
	shortestPrefix := prefixes[0]
	prefixLen := len(shortestPrefix)
	if prefixLen == 0 {
		return sql
	}

	for i, line := range lines {
		if i == 0 {
			if strings.HasPrefix(line, shortestPrefix) {
				lines[i] = line[prefixLen:]
			}

			// Otherwise don't modify the first line.
			continue
		}

		if strings.TrimSpace(line) == "" {
			lines[i] = ""
		} else {
			lines[i] = line[prefixLen:]
		}
	}

	return strings.Join(lines, "\n")
}
