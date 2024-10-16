package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/andrew-d/homeauth/internal/db"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/gorilla/csrf"
	"golang.org/x/crypto/chacha20poly1305"
)

func (s *idpServer) serveWebauthnBeginLogin(w http.ResponseWriter, r *http.Request) {
	s.logger.Debug("beginning WebAuthn login")

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

	encodedSession, err := s.encodeWebAuthnSession(user.Email, sessionData)
	if err != nil {
		s.logger.Error("failed to encode WebAuthn session data", errAttr(err))
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	// Return the registration data to the client.
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]any{
		"options": options,
		"session": encodedSession,
	}); err != nil {
		s.logger.Error("failed to JSON-encode WebAuthn response", errAttr(err))
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
}

func (s *idpServer) servePostLoginWebauthn(w http.ResponseWriter, r *http.Request, user *db.User) {
	// Decode the session data from the form.
	encryptedSession := r.FormValue("webauthn_session")
	if encryptedSession == "" {
		s.logger.Error("missing webauthn_session")
		http.Error(w, "missing webauthn_session", http.StatusBadRequest)
		return
	}
	var sessionData webauthn.SessionData
	if err := s.decodeWebAuthnSession(&sessionData, user.Email, encryptedSession); err != nil {
		s.logger.Error("failed to decode WebAuthn session", errAttr(err))
		http.Error(w, "invalid webauthn_session", http.StatusBadRequest)
		return
	}

	s.logger.Debug("finishing WebAuthn login", "user", user.Email)

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

	cred, err := s.webAuthn.ValidateLogin(wuser, sessionData, par)
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

	http.Redirect(w, r, s.getNextURL(r), http.StatusSeeOther)
}

// appendWebAuthnSessionAD appends the associated data for an encrypted
// WebAuthn session to out.
//
// The associated data that we use to includes a fixed string and then the
// user's email, which adds further protection against session data being
// confused between users.
func appendWebAuthnSessionAD(out []byte, user string) []byte {
	out = append(out, []byte("webauthn-session-data\x00")...)
	out = append(out, []byte(user)...)
	return out
}

func (s *idpServer) encodeWebAuthnSession(user string, sessionData *webauthn.SessionData) (string, error) {
	// Encrypt the session data and send it to the client; we expect that
	// the client will return it as-is without modification during the
	// login POST request.
	sessionBytes, err := json.Marshal(sessionData)
	if err != nil {
		return "", fmt.Errorf("marshaling session data: %w", err)
	}

	// Generate random nonce; should never fail because rand.Read doesn't
	// return an error on modern systems / with modern Go.
	var nonce [chacha20poly1305.NonceSizeX]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		panic(err)
	}

	// Encrypt, then append nonce to encrypted bytes.
	associatedData := appendWebAuthnSessionAD(nil, user)
	encBytes := s.webAuthnAEAD.Seal(sessionBytes[:0], nonce[:], sessionBytes, associatedData)
	encBytes = append(encBytes, nonce[:]...)

	// Encode to base64
	b64 := base64.URLEncoding.EncodeToString(encBytes)
	return b64, nil
}

func (s *idpServer) decodeWebAuthnSession(into *webauthn.SessionData, user, encoded string) error {
	encBytes, err := base64.URLEncoding.DecodeString(encoded)
	if err != nil {
		return fmt.Errorf("decoding base64: %w", err)
	}

	// Remove nonce from the end of the data
	if len(encBytes) < chacha20poly1305.NonceSizeX {
		s.logger.Error("invalid webauthn_session: too short",
			"length", len(encBytes),
			"nonce_size", chacha20poly1305.NonceSizeX,
		)
		return fmt.Errorf("invalid WebAuthn session: too short")
	}
	nonce := encBytes[len(encBytes)-chacha20poly1305.NonceSizeX:]
	encBytes = encBytes[:len(encBytes)-chacha20poly1305.NonceSizeX]

	// Decrypt the session data.
	associatedData := appendWebAuthnSessionAD(nil, user)
	plaintext, err := s.webAuthnAEAD.Open(encBytes[:0], nonce[:], encBytes, associatedData)
	if err != nil {
		return fmt.Errorf("decrypting WebAuthn session data: %w", err)
	}

	// Deserialize the session data.
	if err := json.Unmarshal(plaintext, into); err != nil {
		return fmt.Errorf("unmarshaling WebAuthn session data: %w", err)
	}
	return nil
}

func (s *idpServer) serveWebAuthn(w http.ResponseWriter, r *http.Request) {
	user := s.mustLoadUser(r.Context())

	// Show all webauthn credentials to the user
	var creds []*db.WebAuthnCredential
	s.db.Read(func(data *data) {
		creds = data.WebAuthnCreds[user.UUID]
	})

	if err := s.templates.ExecuteTemplate(w, "webauthn.html.tmpl", map[string]any{
		"User":        user,
		"Credentials": creds,
		"CSRFToken":   csrf.Token(r),
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
	user := s.mustLoadUser(ctx)

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

	// Marshal the session data as JSON and persist it as bytes, to avoid
	// any round-trip marshaling issues.
	sessionDataBytes, err := json.Marshal(sessionData)
	if err != nil {
		s.logger.Error("failed to marshal session data", errAttr(err))
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	// Store the session data in the session, and persist it.
	s.smgr.Put(ctx, skeyWebAuthnSession, sessionDataBytes)

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
	user := s.mustLoadUser(ctx)

	wuser := &webAuthnUser{user: user}
	s.db.Read(func(data *data) {
		wuser.credentials = data.WebAuthnCreds[user.UUID]
	})

	// Load the JSON-encoded bytes of the session data. We're handling a
	// registration response from the client. We expect to have a current
	// WebAuthn session.
	sessionDataBytes := s.smgr.GetBytes(ctx, skeyWebAuthnSession)
	if sessionDataBytes == nil {
		s.logger.Error("no WebAuthn session found in session")
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	var sessionData webauthn.SessionData
	if err := json.Unmarshal(sessionDataBytes, &sessionData); err != nil {
		s.logger.Error("failed to unmarshal WebAuthn session data", errAttr(err))
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	// We can't use the webauthn.FinishRegistration function here because it
	// expects a raw *http.Request and decodes the response from the body,
	// whereas we have the friendly name for the credential as well.
	//
	// Instead decode it ourselves.
	var requestBody struct {
		WebAuthn     protocol.CredentialCreationResponse `json:"webauthn"`
		FriendlyName string                              `json:"friendly_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
		s.logger.Error("failed to decode request body", errAttr(err))
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	// TODO: do what the webauthn.FinishRegistration function does here and
	// check if there's any trailing data?
	parsed, err := requestBody.WebAuthn.Parse()
	if err != nil {
		s.logger.Error("failed to parse WebAuthn response", webAuthnErrAttr(err)...)
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	cred, err := s.webAuthn.CreateCredential(wuser, sessionData, parsed)
	if err != nil {
		s.logger.Error("failed to finish registration", webAuthnErrAttr(err)...)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	// Persist the newly-created Credential in the database.
	if err := s.db.Write(func(data *data) error {
		if data.WebAuthnCreds == nil {
			data.WebAuthnCreds = make(map[string][]*db.WebAuthnCredential)
		}
		data.WebAuthnCreds[user.UUID] = append(data.WebAuthnCreds[user.UUID], &db.WebAuthnCredential{
			Credential:   *cred, // TODO: don't love the * here
			UserUUID:     user.UUID,
			FriendlyName: requestBody.FriendlyName,
		})

		return nil
	}); err != nil {
		s.logger.Error("failed to save WebAuthn credential", errAttr(err))
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	// Clear the current WebAuthn session now that the user has
	// used it to register; we don't need it.
	s.smgr.Remove(ctx, skeyWebAuthnSession)

	s.logger.Info("WebAuthn registration complete",
		"user", user.Email,
		"credential_id", cred.ID,
		"credential_friendly_name", requestBody.FriendlyName,
	)

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

func webAuthnErrAttr(err error) []any {
	if err == nil {
		return []any{slog.String("error", "<nil>")}
	}

	var protocolErr *protocol.Error
	if !errors.As(err, &protocolErr) {
		return []any{errAttr(err)}
	}

	return []any{
		errAttr(err),
		slog.String("protocol_error_type", protocolErr.Type),
		slog.String("protocol_error_details", protocolErr.Details),
		slog.String("protocol_error_debug", protocolErr.DevInfo),
	}
}
