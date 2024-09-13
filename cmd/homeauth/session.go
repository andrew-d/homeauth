package main

import (
	"context"
	"net/http"

	"github.com/andrew-d/homeauth/internal/db"
)

const sessionCookieName = "session"

var sessionCtxKey = new(int)

// getSession will retrieve a session from the request, if it exists.
func (s *idpServer) getSession(r *http.Request, tx *db.Tx) (*db.Session, bool) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return nil, false
	}

	ctx := r.Context()
	session, err := tx.GetSessionByID(ctx, cookie.Value)
	if err != nil {
		return nil, false
	}
	return session, true
}

// requireSession is a middleware that looks up a session from the provided
// request and stores it in the request's Context.
//
// If no session is found, the error handler is called and the wrapped function
// is not called.
func (s *idpServer) requireSession(errHandler http.Handler) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rx, err := s.db.ReadTx(r.Context())
			if err != nil {
				s.logger.Error("failed to open read transaction", errAttr(err))
				errHandler.ServeHTTP(w, r)
				return
			}

			session, ok := s.getSession(r, rx)
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

// mustSessionFromContext retrieves a session from the provided context, or
// panics if it does not exist.
func (s *idpServer) mustSessionFromContext(ctx context.Context) *db.Session {
	session, ok := s.sessionFromContext(ctx)
	if !ok {
		panic("session not found in context")
	}
	return session
}

// mustUserFromContext retrieves a user from the provided context based on the
// stored session.
func (s *idpServer) mustUserFromContext(ctx context.Context) *db.User {
	session := s.mustSessionFromContext(ctx)

	rx, err := s.db.ReadTx(ctx)
	if err != nil {
		panic(err)
	}

	user, err := rx.GetUser(ctx, session.UserID)
	if err != nil {
		panic(err)
	}
	return user
}

// putSession will store a session in the database and set a cookie on the
// response with the session ID.
//
// A new session ID will be generated and stored in the provided session
// cookie.
func (s *idpServer) putSession(w http.ResponseWriter, r *http.Request, tx *db.Tx, session *db.Session) error {
	session.ID = randHex(32)

	if err := tx.PutSession(r.Context(), session); err != nil {
		s.logger.Error("failed to put session", errAttr(err))
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
