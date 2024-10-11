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

	"github.com/alexedwards/scs/v2"
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
	"github.com/andrew-d/homeauth/securecookie"
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

	te, err := templates.New(logger.With(slog.String("service", "templateEngine")))
	if err != nil {
		fatal(logger, "failed to initialize templates", errAttr(err))
	}

	idp := &idpServer{
		logger:         logger.With(slog.String("service", "idp")),
		serverURL:      *serverURL,
		serverHostname: u.Hostname(),
		db:             db,
		hasher:         hasher,
		triggerEmailCh: make(chan struct{}, 1),
		templates:      te,
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
	hasher         *pwhash.Hasher
	triggerEmailCh chan struct{}
	templates      templates.TemplateEngine

	// The following fields are initialized by the initializeConfig
	// function.

	jsonFileStore  *jsonFileStore
	smgr           *scs.SessionManager
	webAuthn       *webauthn.WebAuthn
	webAuthnCookie *securecookie.SecureCookie[webAuthnUnauthenticatedData]

	// cookiesSecure is whether cookies set by this service should have the
	// Secure flag set. This will be false if we're in dev mode or if the
	// server's hostname is 'localhost' or a localhost IP address.
	cookiesSecure bool
}

// initializeConfig will initialize various objects and configuration fields in
// the idpServer, reading from the database, generating keys if necessary, and
// validating configuration that is present.
func (s *idpServer) initializeConfig() error {
	if buildtags.IsDev {
		s.cookiesSecure = false
	} else if slices.Contains([]string{"localhost", "127.0.0.1", "::1"}, s.serverHostname) {
		s.cookiesSecure = false
	} else {
		s.cookiesSecure = true
	}

	// Set up authenticated sessions
	s.jsonFileStore = &jsonFileStore{
		db:      s.db,
		timeNow: time.Now,
	}
	s.smgr = scs.New()
	s.smgr.Store = s.jsonFileStore
	//s.smgr.Codec = // TODO: a JSON codec instead of gob?
	s.smgr.Cookie.Name = sessionCookieName
	s.smgr.Cookie.HttpOnly = true
	s.smgr.Cookie.Path = "/"
	s.smgr.Cookie.SameSite = http.SameSiteStrictMode
	s.smgr.Cookie.Secure = s.cookiesSecure

	// If there's an invalid session in the database, we can get into a
	// broken state where we can't load anything; try deserializing all
	// sessions and clear them all if there's an error.
	sessionsOk := s.validateStoredSessions()

	// Verify the config in the database.
	var (
		secureCookieKey []byte
		errs            []error
	)
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

		// Generate securecookie key if it doesn't exist.
		if len(data.Config.SecureCookieKey) != securecookie.KeyLength {
			data.Config.SecureCookieKey = securecookie.NewKey()
		}
		secureCookieKey = data.Config.SecureCookieKey

		// Clear sessions if needed
		if !sessionsOk {
			data.Sessions = make(map[string]scsSession)
		}

		// Load cookie domain.
		s.smgr.Cookie.Domain = data.Config.CookieDomain

		return nil
	}); err != nil {
		errs = append(errs, err)
	}

	// Create securecookie to store WebAuthn unauthenticated data during login.
	var err error
	s.webAuthnCookie, err = securecookie.New[webAuthnUnauthenticatedData](secureCookieKey)
	if err != nil {
		errs = append(errs, fmt.Errorf("creating securecookie: %w", err))
	}

	// Create WebAuthn configuration and structure.
	wconfig := makeWebAuthnConfig(s.serverURL)
	s.webAuthn, err = webauthn.New(wconfig)
	if err != nil {
		errs = append(errs, fmt.Errorf("initializing WebAuthn: %w", err))
	}

	return errors.Join(errs...)
}

func (s *idpServer) validateStoredSessions() (valid bool) {
	allStore, ok := s.smgr.Store.(scs.IterableStore)
	if !ok {
		return true
	}

	allSessions, err := allStore.All()
	if err != nil {
		s.logger.Warn("could not list all sessions; clearing them", errAttr(err))
		return false
	}

	errCount := 0
	for _, session := range allSessions {
		if _, _, err := s.smgr.Codec.Decode(session); err != nil {
			errCount++
		}
	}
	if errCount > 0 {
		s.logger.Warn("error decoding some stored sessions; clearing them",
			"num_total", len(allSessions),
			"num_error", errCount,
		)
		return false
	}
	return true
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
	//
	// NOTE: setting IdleTimeout on the scs.SessionManager will cause the
	// middleware to create a new DB-backed session for every client, which
	// can be a bad idea.
	r.Use(s.smgr.LoadAndSave)

	// TODO: Access-Control-Allow-Origin header for certain endpoints

	// Create a Group for all the routes that require CSRF protection.
	r.Group(func(r chi.Router) {
		r.Use(csrf.Protect(
			csrfKey,
			csrf.Secure(s.cookiesSecure),
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
		err := s.templates.ExecuteTemplate(w, "index.html.tmpl", nil)
		if err != nil {
			s.logger.Error("failed to render page", "page", "index.html.tmpl", "err", err)
			http.Error(w, "failed to render page", http.StatusInternalServerError)
		}
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

	if err := s.templates.ExecuteTemplate(w, "login.html.tmpl", map[string]any{
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
	ctx := r.Context()
	if err := s.smgr.RenewToken(ctx); err != nil {
		s.logger.Error("failed to renew session token", errAttr(err))
		return err
	}
	s.smgr.Put(ctx, skeyUserUUID, user.UUID)

	s.logger.Info("logged in user",
		"username", user.Email,
		"user_uuid", user.UUID,
		//"session_id", session.ID,
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
	user := s.mustLoadUser(r.Context())

	// NOTE: this iterates over and deserializes all sessions from JSON,
	// which is very inefficient. It's fine in this case because we don't
	// expect to have too many users, but worth noting.
	var numSessions int
	if allStore, ok := s.smgr.Store.(scs.IterableStore); ok {
		if allSessions, err := allStore.All(); err == nil {
			for _, session := range allSessions {
				_, values, err := s.smgr.Codec.Decode(session)
				if err != nil {
					continue
				}
				if values[skeyUserUUID] == user.UUID {
					numSessions++
				}
			}
		} else {
			s.logger.Error("failed to iterate over all sessions", errAttr(err))
		}
	}

	if err := s.templates.ExecuteTemplate(w, "account.html.tmpl", map[string]any{
		"User":           user,
		"NumSessions":    numSessions,
		csrf.TemplateTag: csrf.TemplateField(r),
	}); err != nil {
		s.logger.Error("failed to render account template", errAttr(err))
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}

func (s *idpServer) serveLogout(w http.ResponseWriter, r *http.Request) {
	// Load the currently logged-in user and then destroy the session.
	userUUID := s.smgr.GetString(r.Context(), skeyUserUUID)
	s.smgr.Destroy(r.Context())
	if userUUID == "" {
		// Nothing to do
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// NOTE: by default we don't remove all sessions for the user, just the
	// currently-authenticated one. This seems like the correct UX
	// tradeoff, so that we don't e.g. invalidate a session on a user's
	// iPhone when they log out on their laptop.

	// TODO: we should use a flash message here or something
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *idpServer) serveLogoutOtherSessions(w http.ResponseWriter, r *http.Request) {
	// Load the currently logged-in user and session token.
	ctx := r.Context()
	userUUID := s.smgr.GetString(ctx, skeyUserUUID)
	token := s.smgr.Token(ctx)

	if userUUID == "" || token == "" {
		// Unexpected
		s.logger.Error("missing user UUID or session token", "user_uuid", userUUID, "token", token)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// Delete all sessions except the current one.
	if err := s.smgr.Iterate(ctx, func(ctx context.Context) error {
		sessUserUUID := s.smgr.GetString(ctx, skeyUserUUID)
		if sessUserUUID != userUUID {
			return nil
		}

		if sessToken := s.smgr.Token(ctx); sessToken != token {
			return s.smgr.Destroy(ctx)
		}
		return nil
	}); err != nil {
		s.logger.Error("failed to destroy other sessions", errAttr(err))
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	// Remove all magic login links for the user.
	if err := s.db.Write(func(data *data) error {
		for token, ml := range data.MagicLinks {
			if ml.UserUUID == userUUID {
				delete(data.MagicLinks, token)
			}
		}
		return nil
	}); err != nil {
		s.logger.Error("failed to remove magic links", errAttr(err))
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

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
