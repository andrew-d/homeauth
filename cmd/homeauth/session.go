package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"log/slog"
	"net/http"

	"github.com/andrew-d/homeauth/internal/db"
)

// sessionData is the data we store in our session store.
type sessionData struct {
	UserUUID        string `json:"u,omitempty"`
	WebAuthnSession []byte `json:",omitempty"`

	// PasswordBinding is an (optional) hash of the user's password hash,
	// that binds this session to the current password.
	//
	// It is only set if the user logged in with a password, and is used to
	// verify that the user's password hasn't changed since the session was
	// created.
	PasswordBinding string `json:"pb,omitempty"`
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
			var user *db.User
			s.db.Read(func(d *data) {
				user = d.Users[session.UserUUID]
			})
			if user == nil {
				s.logger.Warn("session refers to non-existent user",
					"user_uuid", session.UserUUID)
				errHandler.ServeHTTP(w, r)
				return
			}

			// If the user logged in with a password, verify that the password
			// hash hasn't changed since the session was created.
			if session.PasswordBinding != "" && getPasswordBinding(user) != session.PasswordBinding {
				s.logger.Warn("password hash has changed since session was created",
					"user_uuid", session.UserUUID)
				errHandler.ServeHTTP(w, r)
				return
			}

			AddRequestLogAttrs(r, slog.String("user_uuid", session.UserUUID))
			next.ServeHTTP(w, r)
		})
	}
}

func getPasswordBinding(user *db.User) string {
	// If the user has no password, we don't need to bind the session to it.
	if user.PasswordHash == "" {
		return ""
	}

	// Otherwise, bind the session to the user's password hash.
	//
	// To avoid keeping a copy of the user's password hash around, we hash it
	// again. This is safe because the password hash is already a hash of the
	// user's password, so hashing it again doesn't weaken the security; we
	// also do not need to salt it for the same reason.
	hash := sha256.Sum256([]byte(user.PasswordHash))
	return base64.RawStdEncoding.EncodeToString(hash[:])
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
