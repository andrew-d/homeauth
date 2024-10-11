package main

import (
	"context"
	"net/http"

	"github.com/andrew-d/homeauth/internal/db"
)

const (
	sessionCookieName = "homeauth_session"

	skeyUserUUID        = "user_uuid"
	skeyWebAuthnSession = "webauthn_session"
)

func (s *idpServer) requireLogin(errHandler http.Handler) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// debugging
			s.logger.Debug("session info",
				"keys", s.smgr.Keys(r.Context()),
			)

			userUUID := s.smgr.GetString(r.Context(), skeyUserUUID)
			if userUUID == "" {
				errHandler.ServeHTTP(w, r)
				return
			}

			// Verify this is a valid user
			var found bool
			s.db.Read(func(d *data) {
				_, found = d.Users[userUUID]
			})
			if !found {
				errHandler.ServeHTTP(w, r)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func (s *idpServer) mustLoadUser(ctx context.Context) (user *db.User) {
	userUUID := s.smgr.GetString(ctx, skeyUserUUID)
	if userUUID == "" {
		panic("no user in session")
	}

	s.db.Read(func(d *data) {
		user = d.Users[userUUID]
	})
	if user == nil {
		panic("user not found")
	}
	return
}
