package main

import (
	"context"
	"net/http"

	"github.com/andrew-d/homeauth/internal/db"
)

const sessionCookieName = "session"

var sessionCtxKey = new(int)

// getSession will retrieve a session from the request, if it exists.
func (s *idpServer) getSession(data *data, r *http.Request) (*db.Session, bool) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return nil, false
	}

	sess, ok := data.Sessions[cookie.Value]
	return sess, ok
}

// requireSession is a middleware that looks up a session from the provided
// request and stores it in the request's Context.
//
// If no session is found, the error handler is called and the wrapped function
// is not called.
func (s *idpServer) requireSession(errHandler http.Handler) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var (
				session *db.Session
				ok      bool
			)
			s.db.Read(func(d *data) {
				session, ok = s.getSession(d, r)
			})
			if !ok {
				s.logger.Debug("no session found")
				errHandler.ServeHTTP(w, r)
				return
			}

			ctx := context.WithValue(r.Context(), sessionCtxKey, session)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// sessionFromContext retrieves a session from the provided context.
func (s *idpServer) sessionFromContext(ctx context.Context) (*db.Session, bool) {
	session, ok := ctx.Value(sessionCtxKey).(*db.Session)
	return session, ok
}

// userFromContext retrieves a user from the provided context based on the
// stored session. It assumes that there's a valid session in the context, as
// would be stored with requireSession; if not, it will panic.
func (s *idpServer) mustUserFromContext(ctx context.Context) *db.User {
	var user *db.User
	s.db.Read(func(d *data) {
		session, ok := s.sessionFromContext(ctx)
		if !ok {
			return
		}

		user, ok = d.Users[session.UserID]
		if !ok {
			s.logger.Warn("session refers to non-existent user",
				"session_id", session.ID,
				"user_id", session.UserID)
		}
	})
	if user == nil {
		panic("no user found in context")
	}
	return user
}

// putSession will store a session in the database and set a cookie on the
// response with the session ID.
//
// A new session ID will be generated and stored in the provided session
// cookie.
func (s *idpServer) putSession(w http.ResponseWriter, r *http.Request, session *db.Session) error {
	session.ID = randHex(32)

	err := s.db.Write(func(d *data) error {
		if d.Sessions == nil {
			d.Sessions = make(map[string]*db.Session)
		}
		d.Sessions[session.ID] = session
		return nil
	})
	if err != nil {
		return err
	}

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    session.ID,
		Expires:  session.Expiry,
		HttpOnly: true,
		Secure:   r.URL.Scheme == "https",
		SameSite: http.SameSiteStrictMode,
	})
	return nil
}
