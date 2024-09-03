package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
)

// DB is the main database interface.
type DB struct {
	mu     sync.RWMutex // protects following
	closed bool
	f      *os.File
	data   dbData
}

// dbData is the on-disk representation of the database.
type dbData struct {
	Users map[string]*DBUser `json:"users"` // keyed by email
}

// DBUser is the type of a user in the database.
type DBUser struct {
	Email        string `json:"email"`
	PasswordHash string `json:"password_hash"`
}

// NewDB creates a new DB.
func NewDB(path string) (*DB, error) {
	return newDB(path)
}

func newDB(path string) (db *DB, retErr error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return nil, fmt.Errorf("opening file: %w", err)
	}
	defer func() {
		if retErr != nil {
			f.Close()
		}
	}()

	db = &DB{f: f}

	// If the file contains any data, then decode it as JSON.
	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("getting file info: %w", err)
	}
	if fi.Size() > 0 {
		if err := json.NewDecoder(f).Decode(&db.data); err != nil {
			return nil, fmt.Errorf("decoding JSON: %w", err)
		}
	}
	return db, nil
}

// Close closes the database.
func (db *DB) Close() error {
	db.mu.Lock()
	defer db.mu.Unlock()
	if db.closed {
		return nil
	}

	err := db.f.Close()
	db.closed = true
	db.f = nil
	return err
}

// persist will write the contents of the database to disk.
func (db *DB) persist() error {
	db.mu.RLock()
	defer db.mu.RUnlock()
	return db.persistLocked()
}

func (db *DB) persistLocked() error {
	if db.closed {
		return os.ErrClosed
	}

	// Seek to the beginning of the file and truncate it.
	if _, err := db.f.Seek(0, 0); err != nil {
		return fmt.Errorf("seeking to beginning of file: %w", err)
	}
	if err := db.f.Truncate(0); err != nil {
		return fmt.Errorf("truncating file: %w", err)
	}

	// Now rewrite the entire file.
	if err := json.NewEncoder(db.f).Encode(&db.data); err != nil {
		return fmt.Errorf("writing JSON to file: %w", err)
	}

	// Ensure that data is synced to disk.
	if err := db.f.Sync(); err != nil {
		return fmt.Errorf("syncing file to disk: %w", err)
	}
	return nil
}

// GetUser retrieves a user from the database.
func (db *DB) GetUser(email string) (*DBUser, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()
	return db.getUserLocked(email)
}

func (db *DB) getUserLocked(email string) (*DBUser, error) {
	if db.closed {
		return nil, os.ErrClosed
	}
	user, ok := db.data.Users[email]
	if !ok {
		return nil, nil
	}
	return user, nil
}

// PutUser adds a user to the database.
func (db *DB) PutUser(user *DBUser) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	return db.putUserLocked(user)
}

func (db *DB) putUserLocked(user *DBUser) error {
	if db.closed {
		return os.ErrClosed
	}

	// Add the user to the database and then persist.
	if db.data.Users == nil {
		db.data.Users = make(map[string]*DBUser)
	}
	db.data.Users[user.Email] = user
	return db.persistLocked()
}
