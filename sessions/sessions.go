package sessions

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"time"
)

const sessionCookieName = "session"

// ErrNotFound is returned by the Find method of a session store when the
// requested session is not found.
var ErrNotFound = errors.New("session not found")

// Store is the interface that must be implemented by persistent session
// stores. It is modeled after the session store interface in the scs package.
// Each Store can define how it marshals and unmarshals the provided type
// parameter T, if necessary.
//
// All methods must be safe for concurrent use.
type Store[T any] interface {
	// Find should return the data for a session token from the store,
	// storing it into the 'into' parameter. If the session token is not
	// found, tampered with, or is expired, the error return value should
	// be ErrNotFound.
	Find(ctx context.Context, token string, into *T) (err error)

	// Delete should remove the session token and corresponding data from the
	// store. If the token does not exist then Delete should do nothing and
	// return nil (and not an error).
	Delete(ctx context.Context, token string) (err error)

	// Commit should add the session token and data to the store, with the
	// given expiry time. If the session token already exists, then the
	// data and expiry time should be overwritten.
	Commit(ctx context.Context, token string, d *T, expiry time.Time) (err error)

	// List should return a list of all valid, non-expired session tokens
	// in the store along with their data.
	List(ctx context.Context) (tokens map[string]T, err error)
}

// CookieOpts is a struct that can be used to configure the session cookie.
//
// A Manager is constructed with a default CookieOpts struct, so you only need
// to modify these values if you want to change the defaults.
type CookieOpts struct {
	// Name is the name of the session cookie. The default is "session".
	Name string
	// Domain is the domain of the session cookie. By default, the domain is
	// the domain the domain that the HTTP request was made to.
	Domain string
	// Path is the path of the session cookie. The default is "/".
	Path string
	// Secure indicates if the session cookie should only be sent over
	// HTTPS. The default is false.
	Secure bool
	// HttpOnly indicates if the session cookie should be accessible only
	// to the server via HTTP (i.e. not in JavaScript). The default is true.
	HttpOnly bool
	// SameSite indicates the SameSite attribute of the session cookie. The
	// default is http.SameSiteStrictMode..
	SameSite http.SameSite
}

// Manager stores and provides accessors for session data for HTTP clients, via
// an opaque token in a cookie that acts as a key for a persistent session data
// store.
//
// The type parameter T is the type of the session data. It must be possible to
// copy with a shallow copy, since shallow copies are returned from the Get
// method and used to update the session data in the Update method.
type Manager[T any] struct {
	ps      Store[T]
	timeNow func() time.Time

	// Log is the logger used by the session manager. It must be provided,
	// and the default value is slog.Default().
	Log *slog.Logger

	// CookieOpts is the configuration for the session cookie.
	// This field cannot be modified when the Manager is in use.
	CookieOpts CookieOpts

	// Lifetime is how long a session should last. The default is 7 days.
	Lifetime time.Duration
}

// New creates a new session manager that uses the provided session store.
func New[T any](ps Store[T]) (*Manager[T], error) {
	ret := &Manager[T]{
		ps:      ps,
		timeNow: time.Now,
		Log:     slog.Default(),
		CookieOpts: CookieOpts{
			Name:     sessionCookieName,
			Path:     "/",
			Secure:   false,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		},
		Lifetime: 7 * 24 * time.Hour,
	}
	return ret, nil
}

// Middleware returns a middleware function that can be used to wrap HTTP
// handlers. The middleware will automatically load and save the session data
// for each request.
func (m *Manager[T]) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Vary", "Cookie")

		// TODO: pool?
		sd := &sessionData[T]{
			state: stateNew, // new = not loaded from the session store
		}

		// First, load the session data from the request.
		if cookie, err := r.Cookie(m.CookieOpts.Name); err == nil {
			// Load from store.
			if err := m.ps.Find(r.Context(), cookie.Value, &sd.Data); err != nil {
				if !errors.Is(err, ErrNotFound) {
					// If we have an error other than "not found", log it.
					m.Log.Error("error loading persistent session", "error", err)

					// Also clear the session data.
					var zero T
					sd.Data = zero
				}
			} else {
				sd.token = cookie.Value
				sd.state = stateLoaded
			}
		}

		// Store the session data in the request context.
		ctx := context.WithValue(r.Context(), contextKey, sd)
		r = r.WithContext(ctx)

		// Wrap the response writer to commit the session data before
		// we write data to the client.
		srw := &sessionResponseWriter[T]{
			ResponseWriter: w,
			req:            r,
			mgr:            m,
		}

		next.ServeHTTP(srw, r)

		// Commit the session data if it hasn't been done already.
		if !srw.written {
			m.onResponse(srw.ResponseWriter, srw.req)
		}
	})
}

// onResponse is called before the response is written to the client.
//
// It returns whether or not to continue writing the response to the client,
// which is false if an error occurred when saving the session data.
func (m *Manager[T]) onResponse(w http.ResponseWriter, r *http.Request) bool {
	ctx := r.Context()

	sd, ok := ctx.Value(contextKey).(*sessionData[T])
	if !ok {
		m.Log.Error("session data not found in request context")
		return true
	}

	switch sd.state {
	case stateDeleted:
		if err := m.ps.Delete(ctx, sd.token); err != nil {
			m.Log.Error("error deleting session", "error", err)

			status := http.StatusInternalServerError
			http.Error(w, http.StatusText(status), status)
			return false
		}

		// Delete the session cookie.
		m.deleteCookie(w, sd.token)

	case stateModified:
		// Commit the session data to the store.
		expiry := m.timeNow().Add(m.Lifetime)
		if err := m.ps.Commit(ctx, sd.token, &sd.Data, expiry); err != nil {
			m.Log.Error("error committing session", "token", sd.token, "error", err)

			// Write an error to the client instead of leaving
			// things in a broken state.
			status := http.StatusInternalServerError
			http.Error(w, http.StatusText(status), status)
			return false
		}

		// Set the session cookie.
		m.setCookie(w, sd.token)

	case stateUnknown:
		m.Log.Warn("session state is unknown", "token", sd.token)
	}

	return true
}

func (m *Manager[T]) deleteCookie(w http.ResponseWriter, token string) {
	cookie := &http.Cookie{
		Name:     m.CookieOpts.Name,
		Value:    "", // clear the value
		Path:     m.CookieOpts.Path,
		Domain:   m.CookieOpts.Domain,
		MaxAge:   -1, // negative = delete
		HttpOnly: m.CookieOpts.HttpOnly,
		SameSite: m.CookieOpts.SameSite,
		Secure:   m.CookieOpts.Secure,
	}
	http.SetCookie(w, cookie)
}

func (m *Manager[T]) setCookie(w http.ResponseWriter, token string) {
	cookie := &http.Cookie{
		Name:     m.CookieOpts.Name,
		Value:    token,
		Path:     m.CookieOpts.Path,
		Domain:   m.CookieOpts.Domain,
		MaxAge:   int(m.Lifetime.Seconds()),
		HttpOnly: m.CookieOpts.HttpOnly,
		SameSite: m.CookieOpts.SameSite,
		Secure:   m.CookieOpts.Secure,
	}
	http.SetCookie(w, cookie)
	w.Header().Add("Cache-Control", `no-cache="Set-Cookie"`)
}

var contextKey = new(int)

type sessionState int

const (
	stateUnknown  sessionState = 0 // session status is unknown
	stateNew      sessionState = 1 // session is newly created, but not yet modified
	stateLoaded   sessionState = 2 // session is loaded from the store, but not yet modified
	stateModified sessionState = 3 // session has been modified
	stateDeleted  sessionState = 4 // session has been deleted
)

func (s sessionState) String() string {
	switch s {
	case stateUnknown:
		return "unknown"
	case stateNew:
		return "new"
	case stateLoaded:
		return "loaded"
	case stateModified:
		return "modified"
	case stateDeleted:
		return "deleted"
	default:
		return "invalid"
	}
}

// sessionData is the type of the session data stored in the request context.
type sessionData[T any] struct {
	// Data is the actual session data.
	Data T

	// token is the session token that was used to load the session data.
	token string

	// state is the current state of the session data.
	state sessionState
}

// Get will return the session data stored in the provided request context. If
// there is no session data in the context, then Get will return the zero value
// of the session data type and false.
//
// Note that even if T is a pointer type, the session will not be updated or
// persisted if modified; you must call Update to save the changes.
func (m *Manager[T]) Get(ctx context.Context) (T, bool) {
	sd, ok := ctx.Value(contextKey).(*sessionData[T])
	if !ok {
		var zero T
		return zero, false
	}
	if sd.state != stateLoaded && sd.state != stateModified {
		var zero T
		return zero, false
	}
	return sd.Data, true
}

// Update will call the provided function to update the session data in the
// request context. When the request is written to the client, the session data
// will be updated in the session store and the session cookie will be set.
//
// If the called function returns a non-nil error, then the session data will
// not be updated.
//
// The provided function will be called with a shallow copy of the session data,
// which will be copied back into the session data stored in the request context
// if the function returns nil. It is the responsibility of the function to
// ensure that any nested pointers are only updated and not mutated in-place;
// otherwise, if the called function returns an error, the session data may be
// left in an inconsistent state.
func (m *Manager[T]) Update(ctx context.Context, f func(*T) error) error {
	sd, ok := ctx.Value(contextKey).(*sessionData[T])
	if !ok {
		return errors.New("session data not found in request context")
	}

	// Make a token for this session if we haven't already.
	if sd.token == "" {
		var buf [32]byte
		if _, err := rand.Read(buf[:]); err != nil {
			panic(err) // never fails on modern Go systems
		}
		sd.token = hex.EncodeToString(buf[:])
	}

	// Shallow-copy the session data so that, if the function fails, we
	// don't overwrite any previously-updated data.
	dataCopy := sd.Data
	if err := f(&dataCopy); err != nil {
		return err
	}

	sd.Data = dataCopy
	sd.state = stateModified
	return nil
}

// Delete will remove the session data from the request context. The session
// data will not be removed from the session store until the response is
// written to the client.
//
// If Delete is called and then Update is called, the session data will be
// written to the session store as if it were new data.
func (m *Manager[T]) Delete(ctx context.Context) {
	sd, ok := ctx.Value(contextKey).(*sessionData[T])
	if !ok {
		return
	}

	sd.state = stateDeleted

	// Also zero out the stored session data, so a future call to Update
	// will operate on the zero value.
	var zero T
	sd.Data = zero
}
