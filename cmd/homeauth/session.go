package main

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/andrew-d/homeauth/internal/db"
)

const sessionCookieName = "session"

var sessionCtxKey = new(int)

// requireLogin is a middleware that looks up a session from the provided
// request, verifies that it represents a logged-in user, and stores it in the
// request's Context.
//
// If no session is found, the error handler is called and the wrapped function
// is not called.
func (s *idpServer) requireLogin(errHandler http.Handler) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			session, ok := s.sessions.getSession(r)
			if !ok {
				s.logger.Debug("no session found")
				errHandler.ServeHTTP(w, r)
				return
			}
			if !session.IsAuthenticated() {
				s.logger.Debug("session is not authenticated")
				errHandler.ServeHTTP(w, r)
				return
			}

			AddRequestLogAttrs(r, slog.String("user_uuid", session.UserUUID))
			ctx := context.WithValue(r.Context(), sessionCtxKey, session)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// sessionFromContext retrieves a session from the provided context.
//
// This function only returns sessions that are authenticated and haven't
// expired. If you need to access a session that may not be authenticated, or
// may be expired, use sessionFromContextOpts.
func (s *idpServer) sessionFromContext(ctx context.Context) (*db.Session, bool) {
	return s.sessionFromContextOpts(ctx, sessionFromContextOpts{})
}

type sessionFromContextOpts struct {
	// AllowExpired is whether to return sessions that have expired.
	AllowExpired bool

	// AllowUnauthenticated is whether sessions that are not authenticated
	// (i.e. represent an anonymous user) should be returned.
	AllowUnauthenticated bool
}

// sessionFromContextOpts retrieves a session from the provided context, with
// the provided options configuring what kind of sessions are allowed.
func (s *idpServer) sessionFromContextOpts(ctx context.Context, opts sessionFromContextOpts) (*db.Session, bool) {
	session, ok := ctx.Value(sessionCtxKey).(*db.Session)
	if !ok {
		return nil, false
	}

	if !opts.AllowUnauthenticated && !session.IsAuthenticated() {
		return nil, false
	}
	if !opts.AllowExpired && !session.Expiry.IsZero() && time.Now().After(session.Expiry.Time) {
		return nil, false
	}
	return session, ok
}

// currentUser returns the current user from the provided context, as set by
// requireLogin (above). It only returns the user if the session is
// authenticated, and will return false if no session is found.
func (s *idpServer) currentUser(ctx context.Context) (*db.User, bool) {
	session, ok := s.sessionFromContext(ctx)
	if !ok {
		return nil, false
	}

	var user *db.User
	s.db.Read(func(d *data) {
		// Re-check that the session exists
		session, ok = d.Sessions[session.ID]
		if !ok {
			return
		}
		// TODO: re-check session expiry?

		user = d.Users[session.UserUUID]
	})

	if user == nil {
		if !ok {
			s.logger.Warn("session refers to non-existent user",
				"session_id", session.ID,
				"user_uuid", session.UserUUID)
		}
		return nil, false
	}
	return user, true
}

// mustUser retrieves the current user from the provided context, as set by
// requireLogin (above). If no user is found, it will panic.
func (s *idpServer) mustUser(ctx context.Context) *db.User {
	user, ok := s.currentUser(ctx)
	if !ok {
		panic("no user found in context")
	}
	return user
}

func sessionCookieFor(sessionID string, secure bool) *http.Cookie {
	return &http.Cookie{
		Name:     sessionCookieName,
		Path:     "/",
		Value:    sessionID,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
	}
}
