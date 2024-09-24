package main

import (
	"net/http"
	"time"

	"github.com/andrew-d/homeauth/internal/db"
	"github.com/andrew-d/homeauth/internal/jsonfile"
)

type sessionManager struct {
	db      *jsonfile.JSONFile[data]
	domain  string
	timeNow func() time.Time
}

// getSession retrieves a session from the request, if it exists.
func (s *sessionManager) getSession(r *http.Request) (sess *db.Session, ok bool) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return nil, false
	}

	s.db.Read(func(d *data) {
		sess, ok = d.Sessions[cookie.Value]
	})
	if !ok {
		return nil, false
	}
	return sess, true
}

// invalidateSession will remove any session associated with the request from
// the database.
//
// This is commonly used when a user logs in or out.
func (s *sessionManager) invalidateSession(r *http.Request) error {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return nil
	}

	return s.db.Write(func(d *data) error {
		delete(d.Sessions, cookie.Value)
		return nil
	})
}

// newSession creates a new session with a random ID, calls the provided
// function to modify it, and then stores it in the database. It returns the
// newly-created session.
func (s *sessionManager) newSession(f func(*db.Session)) (*db.Session, error) {
	session := &db.Session{
		ID: randHex(32),
	}
	f(session)

	if err := s.db.Write(func(d *data) error {
		if d.Sessions == nil {
			d.Sessions = make(map[string]*db.Session)
		}
		d.Sessions[session.ID] = session
		return nil
	}); err != nil {
		return nil, err
	}

	return session, nil
}

// writeSessionCookie writes a session cookie to the provided response describing
// the provided session.
func (s *sessionManager) writeSessionCookie(w http.ResponseWriter, r *http.Request, session *db.Session) {
	cookie := sessionCookieFor(session.ID, s.domain, r.URL.Scheme == "https")

	// Calculate how long the cookie should last based on the current time.
	// We send this as a MaxAge value to the client, instead of an absolute
	// expiry, to be safe even if the client's clock is off.
	if !session.Expiry.IsZero() {
		maxAge := session.Expiry.Sub(time.Now()) / time.Second
		cookie.MaxAge = int(maxAge)
	}

	// Actually set the cookie.
	http.SetCookie(w, cookie)
}

// ensureSession ensures that a session exists in the request, and if not, creates
// a new one and writes the session cookie to the response.
//
// If a new session is created, the provided function is called to modify it.
//
// Note that the provided *http.Request is not modified, so calling r.Cookie()
// will not return a session cookie. If access to such a cookie is needed, it
// should be persisted on the request's context or elsewhere.
func (s *sessionManager) ensureSession(w http.ResponseWriter, r *http.Request, f func(*db.Session)) (*db.Session, error) {
	session, ok := s.getSession(r)
	if ok {
		return session, nil
	}

	session, err := s.newSession(f)
	if err != nil {
		return nil, err
	}

	// Write the session cookie to the response
	s.writeSessionCookie(w, r, session)
	return session, nil
}
