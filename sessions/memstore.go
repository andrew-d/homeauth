package sessions

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

type memStoreData[T any] struct {
	Data   T
	Expiry time.Time
	Token  string
}

// MemStore is an in-memory session store. It is safe for concurrent use.
//
// All methods that take or return a value of type T will perform a shallow
// copy of the type into the provided input or output parameters.
type MemStore[T any] struct {
	mu       sync.RWMutex
	sessions map[string]memStoreData[T]
	timeNow  func() time.Time
}

// NewMemStore returns a new MemStore instance.
func NewMemStore[T any]() *MemStore[T] {
	return &MemStore[T]{
		sessions: make(map[string]memStoreData[T]),
		timeNow:  time.Now,
	}
}

func (ms *MemStore[T]) keyFor(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

// Find implements the Store interface.
func (ms *MemStore[T]) Find(_ context.Context, token string, into *T) error {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	data, ok := ms.sessions[ms.keyFor(token)]
	if !ok {
		return ErrNotFound
	}

	// Unlikely, but confirm that the token actually matches. This should
	// never happen since we use a cryptographic hash.
	if data.Token != token {
		return ErrNotFound
	}

	now := ms.timeNow()
	isExpired := data.Expiry.Before(now)
	if isExpired {
		return ErrNotFound
	}

	*into = data.Data
	return nil
}

// Delete implements the Store interface.
func (ms *MemStore[T]) Delete(_ context.Context, token string) error {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	delete(ms.sessions, ms.keyFor(token))
	return nil
}

// Commit implements the Store interface.
func (ms *MemStore[T]) Commit(_ context.Context, token string, d *T, expiry time.Time) error {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	ms.sessions[ms.keyFor(token)] = memStoreData[T]{
		Data:   *d,
		Expiry: expiry,
		Token:  token,
	}
	return nil
}

// List implements the Store interface.
func (ms *MemStore[T]) List(_ context.Context) (map[string]T, error) {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	tokens := make(map[string]T, len(ms.sessions))
	now := ms.timeNow()
	for _, data := range ms.sessions {
		if data.Expiry.Before(now) {
			continue
		}
		tokens[data.Token] = data.Data
	}
	return tokens, nil
}

// CleanExpired removes all expired sessions from the store. It is the
// responsibility of the user of the store to call this method periodically.
func (ms *MemStore[T]) CleanExpired() {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	now := ms.timeNow()
	for key, data := range ms.sessions {
		if data.Expiry.Before(now) {
			delete(ms.sessions, key)
		}
	}
}
