package db

import (
	"github.com/andrew-d/homeauth/internal/migrate"
)

var migrations = []migrate.Migration{
	migrate.MigrationSQL(`
		CREATE TABLE users (
			id    INTEGER PRIMARY KEY,
			email TEXT NOT NULL,

			password_hash TEXT NOT NULL
		) STRICT
	`),
	migrate.MigrationSQL(`
		CREATE TABLE sessions (
			id      TEXT PRIMARY KEY,
			expiry  INTEGER NOT NULL,
			user_id INTEGER NOT NULL REFERENCES users(id),
			data    TEXT NOT NULL DEFAULT '{}' -- JSON-encoded data
		) STRICT
	`),
}
