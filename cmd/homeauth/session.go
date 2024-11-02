package main

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/andrew-d/homeauth/internal/db"
)

// sessionData is the data we store in our session store.
type sessionData struct {
	UserUUID        string `json:"u,omitempty"`
	WebAuthnSession []byte `json:",omitempty"`
}

// IsAuthenticated returns whether a session represents an authenticated user.
func (d sessionData) IsAuthenticated() bool {
	return d.UserUUID != ""
}

// requireLogin is a middleware that looks up a session from the provided
// request and verifies that it represents a logged-in user.
//
// If no session is found, the error handler is called and the wrapped function
// is not called.
func (s *idpServer) requireLogin(errHandler http.Handler) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			session, ok := s.sessions.Get(r.Context())
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

			// Verify that the user exists
			var validUser bool
			s.db.Read(func(d *data) {
				_, validUser = d.Users[session.UserUUID]
			})
			if !validUser {
				s.logger.Warn("session refers to non-existent user",
					"user_uuid", session.UserUUID)
				errHandler.ServeHTTP(w, r)
				return
			}

			AddRequestLogAttrs(r, slog.String("user_uuid", session.UserUUID))
			next.ServeHTTP(w, r)
		})
	}
}

// mustUser retrieves the current user from the provided context, as enforced
// by requireLogin (above). If no user is found, it will panic.
func (s *idpServer) mustUser(ctx context.Context) *db.User {
	session, ok := s.sessions.Get(ctx)
	if !ok {
		panic("expected session in context")
	}

	var user *db.User
	s.db.Read(func(d *data) {
		user = d.Users[session.UserUUID]
	})

	if user == nil {
		s.logger.Warn("session refers to non-existent user",
			"user_uuid", session.UserUUID)
		panic("no user found in context")
	}
	return user
}
