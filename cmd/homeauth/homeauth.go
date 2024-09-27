package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/gorilla/csrf"
	flag "github.com/spf13/pflag"

	"github.com/andrew-d/homeauth/internal/buildtags"
	"github.com/andrew-d/homeauth/internal/db"
	"github.com/andrew-d/homeauth/internal/jsonfile"
	"github.com/andrew-d/homeauth/internal/templates"
	"github.com/andrew-d/homeauth/pwhash"
	"github.com/andrew-d/homeauth/static"
)

var (
	port      = flag.IntP("port", "p", 8080, "Port to listen on")
	serverURL = flag.String("server-url", fmt.Sprintf("http://localhost:%d", *port), "Public URL of the server")
	dbPath    = flag.String("db", "homeauth.json", "Path to the database file")
	verbose   = flag.BoolP("verbose", "v", false, "Enable verbose logging")
)

func main() {
	flag.Parse()
	logger := slog.Default()

	if *verbose {
		slog.SetLogLoggerLevel(slog.LevelDebug)
	}

	// Parse our server URL to get the hostname.
	u, err := url.Parse(*serverURL)
	if err != nil {
		// No point in continuing if the server URL is invalid.
		fatal(logger, "invalid server URL", "url", *serverURL, errAttr(err))
	}

	// Normalize the server URL by removing any trailing slashes.
	*serverURL = strings.TrimSuffix(*serverURL, "/")

	db, err := jsonfile.Load[data](*dbPath)
	if errors.Is(err, fs.ErrNotExist) {
		db, err = jsonfile.New[data](*dbPath)
	}
	if err != nil {
		fatal(logger, "failed to open database", "path", *dbPath, errAttr(err))
	}

	hasher := pwhash.New(2, 512*1024, 2)

	smgr := &sessionManager{
		db:      db,
		timeNow: time.Now,
	}
	db.Read(func(data *data) {
		smgr.domain = data.Config.CookieDomain
	})

	wconfig := makeWebAuthnConfig(*serverURL)
	webAuthn, err := webauthn.New(wconfig)
	if err != nil {
		fatal(logger, "failed to initialize WebAuthn", errAttr(err))
	}

	idp := &idpServer{
		logger:         logger.With(slog.String("service", "idp")),
		serverURL:      *serverURL,
		serverHostname: u.Hostname(),
		sessions:       smgr,
		db:             db,
		hasher:         hasher,
		webAuthn:       webAuthn,
		triggerEmailCh: make(chan struct{}, 1),
	}
	if err := idp.initializeConfig(); err != nil {
		fatal(logger, "invalid configuration", errAttr(err))
	}
	idp.printConfig()

	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		fatal(logger, "failed to listen", "port", *port, errAttr(err))
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	srv := &http.Server{
		Addr:    fmt.Sprintf(":%d", *port),
		Handler: idp.httpHandler(),
	}
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Serve(ln)
	}()
	defer logger.Info("homeauth finished")

	// Start background cleaners
	go idp.runCleaners(ctx)
	go idp.runEmailLoop(ctx)

	logger.Info("homeauth listening, press Ctrl+C to stop",
		"addr", fmt.Sprintf("http://localhost:%d/", *port))
	select {
	case err := <-errCh:
		fatal(logger, "error starting server", errAttr(err))
	case <-ctx.Done():
		logger.Info("shutting down")
	}

	// Try a graceful shutdown then a hard one.
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()

	err = srv.Shutdown(shutdownCtx)
	if err == nil {
		return
	}

	logger.Error("error shutting down gracefully", errAttr(err))
	if err := srv.Close(); err != nil {
		logger.Error("error during hard shutdown", errAttr(err))
	}
}

func makeWebAuthnConfig(serverURL string) *webauthn.Config {
	u, err := url.Parse(serverURL)
	if err != nil {
		panic(fmt.Sprintf("invalid server URL: %v", err))
	}

	wconfig := &webauthn.Config{
		RPDisplayName: "homeauth",
		RPID:          u.Hostname(), // Generally the FQDN for your site
		RPOrigins: []string{
			serverURL,
		},
	}
	return wconfig
}

type idpServer struct {
	logger         *slog.Logger
	serverURL      string
	serverHostname string
	db             *jsonfile.JSONFile[data]
	sessions       *sessionManager
	hasher         *pwhash.Hasher
	webAuthn       *webauthn.WebAuthn
	triggerEmailCh chan struct{}
}

func (s *idpServer) initializeConfig() error {
	// Verify the config in the database.
	var errs []error
	if err := s.db.Write(func(data *data) error {
		if e := data.Config.Email; e != nil {
			// Verify that the SMTP server is a valid host:port.
			if e.SMTPServer == "" {
				errs = append(errs, errors.New("missing SMTP server"))
			} else if _, _, err := net.SplitHostPort(e.SMTPServer); err != nil {
				errs = append(errs, fmt.Errorf("invalid SMTP server: %w", err))
			}

			useTLS := (e.UseTLS != nil && *e.UseTLS)
			useStartTLS := (e.UseStartTLS != nil && *e.UseStartTLS)
			if useTLS && useStartTLS {
				errs = append(errs, errors.New("cannot use both TLS and StartTLS"))
			}
		}

		// Generate a CSRF key if it's missing.
		if len(data.Config.CSRFKey) != 32 {
			data.Config.CSRFKey = make([]byte, 32)
			if _, err := rand.Read(data.Config.CSRFKey); err != nil {
				errs = append(errs, fmt.Errorf("failed to generate CSRF key: %w", err))
			}
		}

		return nil
	}); err != nil {
		errs = append(errs, err)
	}

	return errors.Join(errs...)
}

func (s *idpServer) printConfig() {
	s.logger.Info("IdP configuration",
		"server_url", s.serverURL,
		"server_hostname", s.serverHostname,
	)
	s.db.Read(func(data *data) {
		s.logger.Info("IdP database",
			"num_users", len(data.Users),
			"num_clients", len(data.Config.Clients),
		)
		for clientID, client := range data.Config.Clients {
			s.logger.Debug("client",
				"name", client.Name,
				"client_id", clientID,
				"redirect_uris", client.RedirectURIs,
			)
		}

		s.logger.Info("IdP cryptographic keys",
			"primary_signing_key", data.Config.PrimarySigningKeyID,
		)
		if e := data.Config.Email; e != nil {
			s.logger.Info("IdP email configuration",
				"from_address", e.FromAddress,
				"smtp_server", e.SMTPServer,
				"smtp_username", e.SMTPUsername,
				"use_tls", e.useTLS(),
				"use_starttls", e.useStartTLS(),
			)
		}
	})
}

func (s *idpServer) httpHandler() http.Handler {
	// Load state from the config file.
	var (
		csrfKey []byte
	)
	s.db.Read(func(data *data) {
		csrfKey = data.Config.CSRFKey
	})

	r := chi.NewRouter()
	r.Use(RequestLogger(s.logger))

	// Ensure that all requests have a valid session cookie, since we use
	// this to store data for e.g. passkeys.
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			now := time.Now()

			session, err := s.sessions.ensureSession(w, r, func(session *db.Session) {
				// Unauthenticated sessions expire when the
				// browser is closed, so we don't set the
				// Expiry value.
				session.IsEphemeral = true
				session.LastActivity = db.JSONTime{now}
			})
			if err != nil {
				s.logger.Error("failed to ensure session", errAttr(err))
				http.Error(w, "internal server error", http.StatusInternalServerError)
				return
			}

			// If the last activity was more than a minute ago, update it.
			if now.Sub(session.LastActivity.Time) > 1*time.Minute {
				if err := s.db.Write(func(data *data) error {
					session = data.Sessions[session.ID] // re-load from the database
					session.LastActivity = db.JSONTime{time.Now()}
					return nil
				}); err != nil {
					s.logger.Error("failed to update session activity", errAttr(err))
					// non-fatal; continue
				}
			}

			// Now that we know we have a session, add it to the request context.
			ctx := context.WithValue(r.Context(), sessionCtxKey, session)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	})

	// TODO: Access-Control-Allow-Origin header for certain endpoints

	// Create a Group for all the routes that require CSRF protection.
	r.Group(func(r chi.Router) {
		// We set the CSRF cookie to always be secure unless we're
		// either (a) in development mode, or (b) listening on
		// localhost or a localhost IP, so that the cookie is applied
		// in tests (which don't use a HTTPS server).
		var csrfSecure bool
		if buildtags.IsDev {
			csrfSecure = false
		} else if slices.Contains([]string{"localhost", "127.0.0.1", "::1"}, s.serverHostname) {
			csrfSecure = false
		}

		r.Use(csrf.Protect(
			csrfKey,
			csrf.Secure(csrfSecure),
			csrf.Path("/"), // Set cookie on all paths
			csrf.RequestHeader("X-CSRF-Token"),
			csrf.ErrorHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				reason := csrf.FailureReason(r)
				s.logger.Warn("CSRF failure",
					"method", r.Method,
					"url", r.URL.String(),
					"reason", reason,
				)

				http.Error(w, fmt.Sprintf("%s - %s", http.StatusText(http.StatusForbidden), reason), http.StatusForbidden)
			})),
		))

		r.Get("/", s.serveIndex)
		// TODO: webfinger for Tailscale compat?
		// TODO: well-known/webauthn?

		// TODO: OIDC RP endpoints

		// Login endpoints for this application
		r.Get("/login", s.serveGetLogin)
		r.Post("/login", s.servePostLogin)

		// Login endpoints for magic link login
		r.Get("/login/check-email", s.serveGetLoginCheckEmail)
		r.Get("/login/magic", s.serveGetMagicLogin)

		// Login endpoints for WebAuthn
		r.Post("/login/webauthn", s.serveWebauthnBeginLogin)

		// Authenticated endpoints
		r.Group(func(r chi.Router) {
			r.Use(s.requireLogin(http.HandlerFunc(s.redirectToLogin)))

			r.Get("/account", s.serveAccount)

			// WebAuthn endpoints that require a session
			r.Get("/account/webauthn", s.serveWebAuthn)
			r.Post("/account/webauthn/register", s.serveWebAuthnRegister)
			r.Post("/account/webauthn/register-complete", s.serveWebAuthnRegisterComplete)

			// Logout
			r.Post("/account/logout", s.serveLogout)
			r.Post("/account/logout-other-sessions", s.serveLogoutOtherSessions)
		})
	})

	// This Group is for all the routes that *don't* require CSRF protection.
	r.Group(func(r chi.Router) {
		r.Get("/.well-known/jwks.json", s.serveJWKS)
		r.Get("/.well-known/openid-configuration", s.serveOpenIDConfiguration)

		// OIDC IdP endpoints
		r.Get("/authorize/public", s.serveAuthorize)
		r.Post("/token", s.serveToken)

		// Per the OIDC spec § 5.3, the "userinfo" endpoint must support GET and POST
		r.Get("/userinfo", s.serveUserinfo)
		r.Post("/userinfo", s.serveUserinfo)

		// API endpoints
		r.Group(func(r chi.Router) {
			r.HandleFunc("/api/verify", s.serveAPIVerify)
		})
	})

	// Add static assets
	if err := static.Iter(func(path string, handler http.Handler) {
		s.logger.Debug("serving static asset", "path", "/"+path)
		r.Method(http.MethodGet, "/"+path, handler)
	}); err != nil {
		s.logger.Warn("failed to add static assets", errAttr(err))
	}

	return r
}

func (s *idpServer) redirectToLogin(w http.ResponseWriter, r *http.Request) {
	// Construct a login URL with the current URL as the redirect.
	vals := url.Values{}
	vals.Set("next", r.URL.String())

	http.Redirect(w, r, "/login?"+vals.Encode(), http.StatusSeeOther)
}

func (s *idpServer) serveIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/" {
		templates.All().ExecuteTemplate(w, "index.html.tmpl", nil)
		return
	}

	http.NotFound(w, r)
}

func (s *idpServer) serveJWKS(w http.ResponseWriter, r *http.Request) {
	keyID, signingKey, err := s.getJWKS()
	if err != nil {
		http.Error(w, "failed to generate key", http.StatusInternalServerError)
		return
	}

	keySet := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{{
			Key:       signingKey.Public(),
			KeyID:     strconv.FormatUint(keyID, 10),
			Algorithm: string(jose.RS256),
			Use:       "sig",
		}},
	}

	w.Header().Set("Content-Type", "application/json")
	jenc := json.NewEncoder(w)
	jenc.SetIndent("", "  ")
	if err := jenc.Encode(keySet); err != nil {
		http.Error(w, "failed to encode key set", http.StatusInternalServerError)
		return
	}
}

func parseRSASigningKey(key *db.SigningKey) (keyID uint64, pkey *rsa.PrivateKey, err error) {
	pkey, err = x509.ParsePKCS1PrivateKey(key.Key)
	if err != nil {
		return
	}

	keyID, err = strconv.ParseUint(key.ID, 10, 64)
	return
}

func (s *idpServer) getJWKS() (keyID uint64, pkey *rsa.PrivateKey, err error) {
	var key *db.SigningKey
	s.db.Read(func(data *data) {
		conf := data.Config
		key = conf.SigningKeys[conf.PrimarySigningKeyID]
	})

	if key != nil {
		keyID, pkey, err = parseRSASigningKey(key)
		if err == nil {
			return
		}

		s.logger.Warn("failed to parse key from database", "keyID", key.ID, errAttr(err))
	}

	err = s.db.Write(func(data *data) error {
		conf := &data.Config

		// Re-check the key in case it was created while we were reading.
		key = conf.SigningKeys[conf.PrimarySigningKeyID]
		if key != nil {
			keyID, pkey, err = parseRSASigningKey(key)
			if err == nil {
				return nil
			}
			s.logger.Warn("failed to parse key from database", "keyID", key.ID, errAttr(err))
		}

		// TODO: generate ECDSA or Ed25519 keys here as well?
		s.logger.Info("generating new RSA key")
		pkey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			s.logger.Error("failed to generate RSA key", errAttr(err))
			return err
		}

		// Get a non-zero uint64 for the key ID.
		var buf [8]byte
		for {
			rand.Read(buf[:]) // never actually errors
			keyID = binary.BigEndian.Uint64(buf[:])
			if keyID != 0 {
				break
			}
		}

		s.logger.Info("generated new RSA key", "keyID", keyID)

		// Store in data for future use.
		conf.PrimarySigningKeyID = fmt.Sprint(keyID)
		if conf.SigningKeys == nil {
			conf.SigningKeys = make(map[string]*db.SigningKey)
		}
		conf.SigningKeys[conf.PrimarySigningKeyID] = &db.SigningKey{
			ID:        conf.PrimarySigningKeyID,
			Algorithm: "RS256",
			Key:       x509.MarshalPKCS1PrivateKey(pkey),
		}
		return nil
	})
	if err != nil {
		s.logger.Error("failed to save key", errAttr(err))
		return 0, nil, err
	}
	return keyID, pkey, nil
}

// TODO: cache me?
func (s *idpServer) getJOSESigner() (jose.Signer, error) {
	keyID, pkey, err := s.getJWKS()
	if err != nil {
		return nil, err
	}

	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.RS256,
		Key:       pkey,
	}, &jose.SignerOptions{
		EmbedJWK: false,
		ExtraHeaders: map[jose.HeaderKey]any{
			jose.HeaderType: "JWT",
			"kid":           fmt.Sprint(keyID),
		},
	})
	if err != nil {
		s.logger.Error("failed to create signer", errAttr(err))
		return nil, err
	}

	return signer, nil
}

func getBearerToken(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", fmt.Errorf("missing authorization header")
	}

	token, ok := strings.CutPrefix(authHeader, "Bearer ")
	if !ok {
		return "", fmt.Errorf("authorization header does not start with Bearer")
	}
	return token, nil
}

func redirectWithError(w http.ResponseWriter, r *http.Request, redirectURI *url.URL, err, desc, state string) {
	if redirectURI == nil {
		http.Error(w, "missing redirect_uri; cannot return error", http.StatusBadRequest)
		return
	}

	// Copy the redirect URL so we can change the query parameters.
	vals := redirectURI.Query()
	vals.Set("error", err)
	if desc != "" {
		vals.Set("error_description", desc)
	}
	if state != "" {
		vals.Set("state", state)
	}

	redirectURI = cloneURL(redirectURI)
	redirectURI.RawQuery = vals.Encode()

	http.Redirect(w, r, redirectURI.String(), http.StatusSeeOther)
}

func cloneURL(u *url.URL) *url.URL {
	clone := *u
	return &clone
}

func validateRedirectURI(ru *url.URL) error {
	if !ru.IsAbs() {
		return fmt.Errorf("redirect_uri must be an absolute URI")
	}
	if ru.Fragment != "" {
		return fmt.Errorf("redirect_uri must not include a fragment")
	}
	if ru.Host == "" {
		return fmt.Errorf("redirect_uri must include a host")
	}
	if ru.Scheme != "http" && ru.Scheme != "https" {
		return fmt.Errorf("redirect_uri must be http or https")
	}
	return nil
}

func (s *idpServer) serveGetLogin(w http.ResponseWriter, r *http.Request) {
	// TODO: verify the 'next' parameter is a valid URL?

	if err := templates.All().ExecuteTemplate(w, "login.html.tmpl", map[string]any{
		"Next":           r.URL.Query().Get("next"),
		csrf.TemplateTag: csrf.TemplateField(r),
	}); err != nil {
		s.logger.Error("failed to render login template", errAttr(err))
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}

func (s *idpServer) servePostLogin(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")

	// Load the user by their email address.
	var user *db.User
	s.db.Read(func(data *data) {
		user = data.userByEmail(username)
	})
	if user == nil {
		s.logger.Info("no such user", "username", username)
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	// Depending on how they want to authenticate, delegate to the right method.
	switch r.FormValue("via") {
	case "password":
		s.servePostLoginPassword(w, r, user)
	case "email":
		s.servePostLoginEmail(w, r, user)
	case "webauthn":
		s.servePostLoginWebauthn(w, r, user)
	case "google":
		// Not yet implemented
		http.Error(w, "not implemented", http.StatusNotImplemented)
		return
	default:
		s.logger.Warn("no authentication method selected", "username", username)
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
}

const allowArbitraryRedirects = true

func (s *idpServer) getNextURL(r *http.Request) string {
	// Redirect the user to the 'next' parameter, or the account page if
	// there's none provided or it's invalid.
	var nextURL string = "/account"
	if next := r.FormValue("next"); next != "" {
		// Validate that the URL is relative and not an open redirect.
		//
		// TODO: this breaks the forward_auth behaviour; for now,
		// disable this and we can figure out if it's a problem or not.
		if allowArbitraryRedirects {
			nextURL = next
		} else {
			if u, err := url.Parse(next); err == nil && !u.IsAbs() {
				nextURL = next
			} else {
				s.logger.Warn("invalid next URL", "next", next, errAttr(err), "is_abs", u.IsAbs())
			}
		}
	}
	return nextURL
}

// loginUserSession logs in a user by creating a session for them. It ignores
// any existing session on the request.
func (s *idpServer) loginUserSession(w http.ResponseWriter, r *http.Request, user *db.User, method string) error {
	session, err := s.sessions.newSession(func(session *db.Session) {
		session.UserUUID = user.UUID
		session.Expiry = db.JSONTime{time.Now().Add(7 * 24 * time.Hour)}
	})
	if err != nil {
		return err
	}

	// Store the session in a cookie.
	s.sessions.writeSessionCookie(w, r, session)

	s.logger.Info("logged in user",
		"username", user.Email,
		"user_uuid", user.UUID,
		"session_id", session.ID,
		"login_method", method,
	)
	return nil
}

func (s *idpServer) servePostLoginPassword(w http.ResponseWriter, r *http.Request, user *db.User) {
	password := r.FormValue("password")
	if !s.hasher.Verify([]byte(password), []byte(user.PasswordHash)) {
		s.logger.Info("invalid password for user", "username", user.Email)
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	// Log the user in by creating a session.
	if err := s.loginUserSession(w, r, user, "password"); err != nil {
		s.logger.Error("failed to log in user", errAttr(err))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, s.getNextURL(r), http.StatusSeeOther)
}

func (s *idpServer) addUser(ctx context.Context, email, password string) error {
	hash := s.hasher.HashString(password)
	return s.db.Write(func(data *data) error {
		for _, u := range data.Users {
			if u.Email == email {
				return fmt.Errorf("user already exists")
			}
		}
		uu := randUUID()
		data.Users[uu] = &db.User{
			UUID:         uu,
			Email:        email,
			PasswordHash: hash,
		}
		return nil
	})
}

func (s *idpServer) serveAccount(w http.ResponseWriter, r *http.Request) {
	user := s.mustUser(r.Context())

	var (
		numSessions int
	)
	s.db.Read(func(data *data) {
		for _, session := range data.Sessions {
			if session.UserUUID == user.UUID {
				numSessions++
			}
		}
	})

	if err := templates.All().ExecuteTemplate(w, "account.html.tmpl", map[string]any{
		"User":           user,
		"NumSessions":    numSessions,
		csrf.TemplateTag: csrf.TemplateField(r),
	}); err != nil {
		s.logger.Error("failed to render account template", errAttr(err))
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}

func (s *idpServer) serveLogout(w http.ResponseWriter, r *http.Request) {
	currSession, ok := s.sessionFromContext(r.Context())
	if !ok {
		s.logger.Error("no session found in context")
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	var cookieDomain string
	s.db.Write(func(data *data) error {
		// Delete all sessions for the current user.
		for _, session := range data.Sessions {
			if session.UserUUID != currSession.UserUUID {
				continue
			}
			delete(data.Sessions, session.ID)
		}

		// Remove all magic login links for the user.
		for token, ml := range data.MagicLinks {
			if ml.UserUUID == currSession.UserUUID {
				delete(data.MagicLinks, token)
			}
		}

		cookieDomain = data.Config.CookieDomain
		return nil
	})

	// Set an empty session cookie as well
	// TODO: this doesn't work; we end up sending a header on login like
	// `session=; session=...` which doesn't work. Removing the session
	// above is enough for now.
	//s.clearCookies(w, r)

	// TODO: factor to sessionManager
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		Domain:   cookieDomain,
		MaxAge:   -1,
		Secure:   r.URL.Scheme == "https",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})

	// TODO: we should use a flash message here or something
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *idpServer) serveLogoutOtherSessions(w http.ResponseWriter, r *http.Request) {
	currSession, ok := s.sessionFromContext(r.Context())
	if !ok {
		s.logger.Error("no session found in context")
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	// Delete all sessions except the current one.
	s.db.Write(func(data *data) error {
		for _, session := range data.Sessions {
			if session.UserUUID != currSession.UserUUID {
				continue
			}
			if session.ID != currSession.ID {
				delete(data.Sessions, session.ID)
			}
		}

		// Remove all magic login links for the user.
		for token, ml := range data.MagicLinks {
			if ml.UserUUID == currSession.UserUUID {
				delete(data.MagicLinks, token)
			}
		}
		return nil
	})

	// TODO: we should use a flash message here or something
	http.Redirect(w, r, "/account", http.StatusSeeOther)
}

func (s *idpServer) clearCookies(w http.ResponseWriter, r *http.Request) {
	for _, cookie := range r.Cookies() {
		s.logger.Info("clearing cookie",
			"name", cookie.Name,
			"value", cookie.Value,
			"path", cookie.Path,
		)
		http.SetCookie(w, &http.Cookie{
			Name:     cookie.Name,
			Value:    "",
			Path:     cookie.Path,
			Domain:   cookie.Domain,
			MaxAge:   -1,
			Secure:   cookie.Secure,
			SameSite: cookie.SameSite,
			HttpOnly: cookie.HttpOnly,
		})
	}
}

func randHex(n int) string {
	buf := make([]byte, n)
	rand.Read(buf)
	return fmt.Sprintf("%x", buf)
}

func randUUID() string {
	return uuid.Must(uuid.NewRandom()).String()
}

func secureCompareStrings(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func fatal(logger *slog.Logger, msg string, args ...any) {
	logger.Error("fatal error: "+msg, args...)
	os.Exit(1)
}

func errAttr(err error) slog.Attr {
	if err == nil {
		return slog.String("error", "<nil>")
	}

	return slog.String("error", err.Error())
}

/*
func loggerHandler() slog.Handler {
	rootDir := "TODO"
	replace := func(groups []string, a slog.Attr) slog.Attr {
		// Remove the directory from the source's filename.
		if a.Key == slog.SourceKey {
			source := a.Value.Any().(*slog.Source)

			// Try to make the source file relative to the root
			// directory of the package; if that's not possible,
			// just use the filename.
			if rel, err := filepath.Rel(rootDir, source.File); err == nil {
				source.File = rel
			} else {
				source.File = filepath.Base(source.File)
			}
		}
		return a
	}
	return slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		AddSource:   true,
		ReplaceAttr: replace,
	})
}
*/
