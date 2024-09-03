package session

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"sync"
	"time"
)

// Store holds session data and manages expiry.
type Store[T any] struct {
	name   string
	expiry time.Duration
	ctxKey any

	// Secure, if set, will force the Secure flag to be set on session
	// cookies even if the request is not using HTTPS.
	Secure bool

	mu       sync.RWMutex
	sessions map[string]T
}

// New creates a new Store for the given type.
func New[T any](name string, expiry time.Duration) *Store[T] {
	return &Store[T]{
		name:     name,
		expiry:   expiry,
		ctxKey:   new(int),
		sessions: make(map[string]T),
	}
}

// Get retrieves a session from the store, if it's present, along with a
// boolean indicating whether it was found.
func (s *Store[T]) Get(r *http.Request) (T, bool) {
	var zero T

	cookie, err := r.Cookie(s.name)
	if err != nil {
		return zero, false
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	session, ok := s.sessions[cookie.Value]
	return session, ok
}

// Put stores a session in the store, and sets a cookie on the response which
// contains the session data.
func (s *Store[T]) Put(w http.ResponseWriter, r *http.Request, session T) {
	sessionID := randBase64String(42) // 42 bytes = 63 characters

	// Expire the session after the configured duration.
	time.AfterFunc(s.expiry, func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		delete(s.sessions, sessionID)
	})

	// Insert our new session into the store.
	s.mu.Lock()
	s.sessions[sessionID] = session
	s.mu.Unlock()

	// Set a cookie on the reponse containing the session ID.
	http.SetCookie(w, &http.Cookie{
		Name:     s.name,
		Value:    sessionID,
		Expires:  time.Now().Add(s.expiry),
		HttpOnly: true,
		Secure:   s.Secure || r.URL.Scheme == "https",
		SameSite: http.SameSiteStrictMode,
	})
}

// Delete will remove a session from the store, based on the session ID in the
// provided request. It returns whether a session was deleted.
func (s *Store[T]) Delete(r *http.Request) bool {
	cookie, err := r.Cookie(s.name)
	if err != nil {
		return false
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.sessions[cookie.Value]
	delete(s.sessions, cookie.Value)
	return ok
}

// LoadContext is a middleware that looks up a session from the provided
// request and stores it in the request's Context. If no session is found, an
// error is returned to the client and the wrapped function is not called.
func (s *Store[T]) LoadContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, ok := s.Get(r)
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), s.ctxKey, session)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// LoadContextWithHandler is similar to LoadContext, but allows you to provide
// a http.Handler that will be called if no session is found. The wrapped
// http.Handler is never called, no matter what the provided handler does.
func (s *Store[T]) LoadContextWithHandler(handler http.Handler) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			session, ok := s.Get(r)
			if !ok {
				handler.ServeHTTP(w, r)
				return
			}

			ctx := context.WithValue(r.Context(), s.ctxKey, session)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// FromContext retrieves a session from the provided context, if it's present.
func (s *Store[T]) FromContext(ctx context.Context) (T, bool) {
	session, ok := ctx.Value(s.ctxKey).(T)
	return session, ok
}

// MustFromContext retrieves a session from the provided context, or otherwise
// aborts the http handler if not.
func (s *Store[T]) MustFromContext(ctx context.Context) T {
	session, ok := s.FromContext(ctx)
	if !ok {
		panic(http.ErrAbortHandler)
	}
	return session
}

// randBase64String returns a string consisting of n random bytes, encoded as
// base64.
func randBase64String(n int) string {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}
