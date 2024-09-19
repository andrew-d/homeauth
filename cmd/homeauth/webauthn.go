package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/andrew-d/homeauth/internal/db"
	"github.com/andrew-d/homeauth/internal/templates"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

func (s *idpServer) serveWebauthnBeginLogin(w http.ResponseWriter, r *http.Request) {
	// Use sessionFromContextOpts to allow unauthenticated sessions.
	session, ok := s.sessionFromContextOpts(r.Context(), sessionFromContextOpts{
		AllowUnauthenticated: true,
	})
	if !ok {
		panic("expected unauthenticated session to exist")
	}

	s.logger.Debug("beginning WebAuthn login",
		"unauthenticated_session_id", session.ID,
	)

	var requestBody struct {
		Username string `json:"username"`
	}
	if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
		s.logger.Error("failed to decode request body", errAttr(err))
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	// Load the user from the database.
	var (
		user  *db.User
		wuser *webAuthnUser
	)
	s.db.Read(func(data *data) {
		user = data.userByEmail(requestBody.Username)
		if user != nil {
			wuser = s.makeWebAuthnUser(data, user)
		}
	})
	if user == nil {
		s.logger.Error("user not found", "username", requestBody.Username)
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}

	options, sessionData, err := s.webAuthn.BeginLogin(wuser)
	if err != nil {
		s.logger.Error("failed to begin login", errAttr(err))
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	// Store the session data in the session, and persist it.
	if err := s.db.Write(func(data *data) error {
		session = data.Sessions[session.ID] // re-load the session
		session.WebAuthnSession = sessionData
		return nil
	}); err != nil {
		s.logger.Error("failed to store session data", errAttr(err))
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	// Return the registration data to the client.
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(options); err != nil {
		s.logger.Error("failed to encode options", errAttr(err))
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
}

func (s *idpServer) servePostLoginWebauthn(w http.ResponseWriter, r *http.Request, user *db.User) {
	// Use sessionFromContextOpts to allow unauthenticated sessions.
	session, ok := s.sessionFromContextOpts(r.Context(), sessionFromContextOpts{
		AllowUnauthenticated: true,
	})
	if !ok {
		panic("expected unauthenticated session to exist")
	}

	s.logger.Debug("finishing WebAuthn login",
		"unauthenticated_session_id", session.ID,
		"user", user.Email,
		"session_has_webauthn", session.WebAuthnSession != nil,
	)

	// If this session doesn't have a WebAuthn session, something is wrong;
	// just redirect the user back to the login page (while preserving the 'next' URL parameter).
	if session.WebAuthnSession == nil {
		vals := url.Values{}
		if nn := r.FormValue("next"); nn != "" {
			vals.Set("next", nn)
		}

		s.logger.Warn("session missing WebAuthn session; redirecting to login")
		http.Redirect(w, r, "/login?="+vals.Encode(), http.StatusSeeOther)
		return
	}

	var (
		wuser *webAuthnUser
	)
	s.db.Read(func(data *data) {
		wuser = s.makeWebAuthnUser(data, user)
	})

	// NOTE: We can't use webauthn.FinishLogin here because it requires a
	// raw *http.Request and decodes the response from the body. However,
	// we pass the assertion as a form field, so just use fetch that and
	// pass it to the validation function directly.
	webauthnResponse := r.FormValue("webauthn_response")
	if webauthnResponse == "" {
		s.logger.Error("missing webauthn_response")
		http.Error(w, "missing webauthn_response", http.StatusBadRequest)
		return
	}

	par, err := protocol.ParseCredentialRequestResponseBody(strings.NewReader(webauthnResponse))
	if err != nil {
		s.logger.Error("failed to parse webauthn response", errAttr(err))
		http.Error(w, "invalid webauthn_response", http.StatusBadRequest)
		return
	}

	cred, err := s.webAuthn.ValidateLogin(wuser, *session.WebAuthnSession, par)
	if err != nil {
		s.logger.Error("failed to validate webauthn response", errAttr(err))
		http.Error(w, "invalid webauthn_response", http.StatusBadRequest)
		return
	}

	if cred.Authenticator.CloneWarning {
		s.logger.Warn("cloned authenticator detected",
			"user", user.Email,
			"credential_id", cred.ID,
		)
	}

	// Update the credential object in the database; this e.g. updates the
	// counter.
	if err := s.db.Write(func(data *data) error {
		for _, c := range data.WebAuthnCreds[user.UUID] {
			if bytes.Equal(c.Credential.ID, cred.ID) {
				c.Credential = *cred
				return nil
			}
		}

		// If we didn't find the credential, something is wrong.
		return fmt.Errorf("credential with ID %x not found", cred.ID)
	}); err != nil {
		s.logger.Error("failed to update credential", errAttr(err))
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	// Log the user in by creating a session.
	if err := s.loginUserSession(w, r, user, "webauthn"); err != nil {
		s.logger.Error("failed to log in user", errAttr(err))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Invalidate and remove the old (unauthenticated) session.
	if err := s.sessions.invalidateSession(r); err != nil {
		// Not a critical error; just log it.
		s.logger.Error("failed to invalidate old session", errAttr(err))
	}

	http.Redirect(w, r, s.getNextURL(r), http.StatusSeeOther)
}

func (s *idpServer) serveWebAuthn(w http.ResponseWriter, r *http.Request) {
	user := s.mustUser(r.Context())

	// Show all webauthn credentials to the user
	var creds []*db.WebAuthnCredential
	s.db.Read(func(data *data) {
		creds = data.WebAuthnCreds[user.UUID]
	})

	if err := templates.All().ExecuteTemplate(w, "webauthn.html.tmpl", map[string]any{
		"User":        user,
		"Credentials": creds,
	}); err != nil {
		s.logger.Error("failed to render webauthn template", errAttr(err))
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
}

func (s *idpServer) serveWebAuthnRegister(w http.ResponseWriter, r *http.Request) {
	// Get the user and the current session (which we use to store the
	// WebAuthn data). We know these exist because we're after a middleware
	// that requires them.
	ctx := r.Context()
	user := s.mustUser(ctx)
	session, _ := s.sessionFromContext(ctx)

	// If the user doesn't have a WebAuthnID yet, generate one.
	if user.WebAuthnID == nil {
		if err := s.db.Write(func(data *data) error {
			// Re-check the user; it might have been updated by
			// another request between the read above and getting
			// the write lock.
			user = data.Users[user.UUID]
			if user.WebAuthnID != nil {
				return nil
			}

			// WebAuthnIDs are 64 random bytes; just pick a random one.
			user.WebAuthnID = make([]byte, 64)
			if _, err := rand.Read(user.WebAuthnID); err != nil {
				return err
			}

			// Re-load the user
			user = data.Users[user.UUID]
			return nil
		}); err != nil {
			s.logger.Error("failed to generate WebAuthn ID", errAttr(err))
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
	}

	var wuser *webAuthnUser
	s.db.Read(func(data *data) {
		wuser = s.makeWebAuthnUser(data, user)
	})

	createOpts, sessionData, err := s.webAuthn.BeginRegistration(wuser)
	if err != nil {
		s.logger.Error("failed to begin registration", errAttr(err))
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	// Store the session data in the session, and persist it.
	if err := s.db.Write(func(data *data) error {
		session = data.Sessions[session.ID] // re-load the session
		session.WebAuthnSession = sessionData
		return nil
	}); err != nil {
		s.logger.Error("failed to store session data", errAttr(err))
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	// Return the registration data to the client.
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(createOpts); err != nil {
		s.logger.Error("failed to encode registration data", errAttr(err))
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
}

func (s *idpServer) serveWebAuthnRegisterComplete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	user := s.mustUser(ctx)
	session, _ := s.sessionFromContext(ctx)

	wuser := &webAuthnUser{user: user}
	s.db.Read(func(data *data) {
		wuser.credentials = data.WebAuthnCreds[user.UUID]
	})

	// We're handling a registration response from the client. We expect to
	// have a current WebAuthn session in our *db.Session type.
	wsession := session.WebAuthnSession
	if wsession == nil {
		s.logger.Error("no WebAuthn session found in session")
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	cred, err := s.webAuthn.FinishRegistration(wuser, *wsession, r)
	if err != nil {
		s.logger.Error("failed to finish registration", errAttr(err))
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	// Persist the newly-created Credential in the database.
	if err := s.db.Write(func(data *data) error {
		if data.WebAuthnCreds == nil {
			data.WebAuthnCreds = make(map[string][]*db.WebAuthnCredential)
		}
		data.WebAuthnCreds[user.UUID] = append(data.WebAuthnCreds[user.UUID], &db.WebAuthnCredential{
			Credential: *cred, // TODO: don't love the * here
			UserUUID:   user.UUID,
		})
		return nil
	}); err != nil {
		s.logger.Error("failed to save WebAuthn credential", errAttr(err))
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	// All good!
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{"status": "ok"}); err != nil {
		s.logger.Error("failed to encode response", errAttr(err))
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
}

// webAuthnUser is a wrapper type that implements the webauthn.User interface.
type webAuthnUser struct {
	user        *db.User
	credentials []*db.WebAuthnCredential
}

var _ webauthn.User = (*webAuthnUser)(nil)

func (s *idpServer) makeWebAuthnUser(data *data, user *db.User) *webAuthnUser {
	wuser := &webAuthnUser{
		user:        user,
		credentials: data.WebAuthnCreds[user.UUID],
	}
	return wuser
}

func (w *webAuthnUser) WebAuthnID() []byte          { return w.user.WebAuthnID }
func (w *webAuthnUser) WebAuthnName() string        { return w.user.Email }
func (w *webAuthnUser) WebAuthnDisplayName() string { return w.user.Email }

func (w *webAuthnUser) WebAuthnCredentials() []webauthn.Credential {
	creds := make([]webauthn.Credential, 0, len(w.credentials))
	for _, cred := range w.credentials {
		creds = append(creds, cred.Credential)
	}
	return creds
}
