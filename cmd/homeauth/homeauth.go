package main

import (
	"context"
	"crypto/cipher"
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
	"golang.org/x/crypto/chacha20poly1305"

	"github.com/andrew-d/homeauth/internal/buildtags"
	"github.com/andrew-d/homeauth/internal/db"
	"github.com/andrew-d/homeauth/internal/jsonfile"
	"github.com/andrew-d/homeauth/internal/templates"
	"github.com/andrew-d/homeauth/listenx"
	"github.com/andrew-d/homeauth/pwhash"
	"github.com/andrew-d/homeauth/sessions"
	"github.com/andrew-d/homeauth/static"
)

var (
	listen        = flag.StringP("listen", "l", "tcp://127.0.0.1:8080", "listen address (e.g. tcp://ip:port, unix://path, systemd://1, etc.)")
	serverURL     = flag.String("server-url", "http://localhost:8080", "public URL of the server")
	dbPath        = flag.String("db", "homeauth.json", "path to the database file")
	cookiesSecure = flag.Bool("cookies-secure", !buildtags.IsDev, "whether cookies should be set with the Secure flag")
	verbose       = flag.BoolP("verbose", "v", false, "enable verbose logging")
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

	sessionStore := newDBSessionStore(db)
	smgr, err := sessions.New(sessionStore)
	if err != nil {
		fatal(logger, "failed to initialize session manager", errAttr(err))
	}
	smgr.Log = logger.With(slog.String("service", "sessions"))
	// TODO: set smgr.Lifetime?

	te, err := templates.New(logger.With(slog.String("service", "templateEngine")))
	if err != nil {
		fatal(logger, "failed to initialize templates", errAttr(err))
	}

	idp := &idpServer{
		logger:         logger.With(slog.String("service", "idp")),
		serverURL:      *serverURL,
		serverHostname: u.Hostname(),
		sessions:       smgr,
		sessionStore:   sessionStore,
		db:             db,
		hasher:         hasher,
		triggerEmailCh: make(chan struct{}, 1),
		templates:      te,
	}
	if err := idp.initializeConfig(); err != nil {
		fatal(logger, "invalid configuration", errAttr(err))
	}
	idp.printConfig()

	ln, err := listenx.Listen(*listen)
	if err != nil {
		fatal(logger, "failed to listen", "spec", *listen, errAttr(err))
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	srv := &http.Server{
		Addr:    ln.Addr().String(),
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
		"addr", fmt.Sprintf("http://%s/", srv.Addr))
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
	sessions       *sessions.Manager[sessionData]
	sessionStore   *dbSessionStore
	hasher         *pwhash.Hasher
	triggerEmailCh chan struct{}
	templates      templates.TemplateEngine

	// webAuthn is the interface for performing WebAuthn operations.
	webAuthn *webauthn.WebAuthn

	// webAuthnAEAD is an AEAD used to encrypt the WebAuthn session data
	// used during login. Before a user logs in, they don't have a session
	// and thus don't have a session cookie that we can use to store the
	// session data.
	//
	// We could use a cookie to store the session data, but we don't need
	// to since we control the client-side code. Instead, we encrypt the
	// session data with a key that is stored on the server and send it to
	// the client, who must send it back in a hidden form field. This way,
	// the client can't tamper with the session data, but we don't need to
	// store any state server-side during logins.
	webAuthnAEAD cipher.AEAD

	// cookiesSecure is whether cookies set by this service should have the
	// Secure flag set. This will be false if we're in dev mode or if the
	// server's hostname is 'localhost' or a localhost IP address.
	//
	// This is a trinary field so that we can distinguish between "insecure
	// cookies" and "we haven't yet set a value".
	//
	// 0 means "unset", 1 means "secure", and 2 means "insecure".
	cookiesSecure int
}

// initializeConfig will initialize various objects and configuration fields in
// the idpServer, reading from the database, generating keys if necessary, and
// validating configuration that is present.
func (s *idpServer) initializeConfig() error {
	// Generate a random key to encrypt WebAuthn session data. It's fine if
	// this is not persisted, since it's only used during login, and it's
	// fine if in-progress logins fail if the server restarts. In most
	// cases, the user won't even notice since the encrypted value is only
	// "live" for as long as it takes to complete the passkey login.
	var webAuthnKey [chacha20poly1305.KeySize]byte
	if _, err := rand.Read(webAuthnKey[:]); err != nil {
		return fmt.Errorf("failed to generate WebAuthn key: %w", err)
	}
	if aead, err := chacha20poly1305.NewX(webAuthnKey[:]); err != nil {
		return fmt.Errorf("failed to create AEAD for WebAuthn key: %w", err)
	} else {
		s.webAuthnAEAD = aead
	}

	if s.cookiesSecure == 0 {
		// If the server URL is localhost or an IP address, we can't set
		// Secure cookies.
		if slices.Contains([]string{"localhost", "127.0.0.1", "::1"}, s.serverHostname) {
			s.cookiesSecure = 2
		} else if *cookiesSecure {
			s.cookiesSecure = 1
		} else {
			s.cookiesSecure = 2 // flag was false
		}
	}
	s.sessions.CookieOpts.Secure = s.cookiesSecure == 1

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

		// Configure session manager.
		s.sessions.CookieOpts.Domain = data.Config.CookieDomain

		return nil
	}); err != nil {
		errs = append(errs, err)
	}

	wconfig := makeWebAuthnConfig(s.serverURL)

	var err error
	s.webAuthn, err = webauthn.New(wconfig)
	if err != nil {
		errs = append(errs, fmt.Errorf("initializing WebAuthn: %w", err))
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

	// Add sessions middleware to all requests, but this isn't committed to
	// our backing store unless the session is modified.
	r.Use(s.sessions.Middleware)

	// TODO: Access-Control-Allow-Origin header for certain endpoints

	// Create a Group for all the routes that require CSRF protection.
	r.Group(func(r chi.Router) {
		r.Use(csrf.Protect(
			csrfKey,
			csrf.Secure(s.cookiesSecure == 1),
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

		// Liveness/readiness endpoints.
		r.Get("/livez", s.serveLivez)
		r.Get("/readyz", s.serveReadyz)
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
	// TODO: double-check if this allows session fixation
	err := s.sessions.Update(r.Context(), func(sd *sessionData) error {
		sd.UserUUID = user.UUID
		return nil
	})
	if err != nil {
		return err
	}

	s.logger.Info("logged in user",
		"username", user.Email,
		"user_uuid", user.UUID,
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

	var numSessions int
	allSessions, err := s.sessionStore.List(r.Context())
	if err == nil {
		for _, session := range allSessions {
			if session.UserUUID == user.UUID {
				numSessions++
			}
		}
	} else {
		s.logger.Error("failed to iterate over all sessions", errAttr(err))
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
	// Destroy any existing session.
	s.sessions.Delete(r.Context())

	// NOTE: by default we don't remove all sessions for the user, just the
	// currently-authenticated one. This seems like the correct UX
	// tradeoff, so that we don't e.g. invalidate a session on a user's
	// iPhone when they log out on their laptop.

	// TODO: we should use a flash message here or something
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *idpServer) serveLogoutOtherSessions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	user := s.mustUser(ctx)
	currentSessionID := s.sessions.GetID(ctx)

	// TODO: this is a bit abstraction-breaking; we reach into the session
	// store, which I don't love.
	allSessions, err := s.sessionStore.List(ctx)
	if err != nil {
		s.logger.Error("failed to list all sessions", errAttr(err))
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	var toRemove []string
	for id, session := range allSessions {
		if session.UserUUID != user.UUID {
			continue
		}
		if id != currentSessionID {
			toRemove = append(toRemove, id)
		}
	}

	// For all sessions that need removing, do so.
	for _, id := range toRemove {
		if err := s.sessionStore.Delete(ctx, id); err != nil {
			s.logger.Error("failed to delete session",
				"session_id", id,
				"user_uuid", user.UUID,
				errAttr(err))
		}
	}

	// Remove all magic login links for the user.
	if err := s.db.Write(func(data *data) error {
		for token, ml := range data.MagicLinks {
			if ml.UserUUID == user.UUID {
				delete(data.MagicLinks, token)
			}
		}
		return nil
	}); err != nil {
		s.logger.Error("failed to delete magic links for user",
			"user_uuid", user.UUID,
			errAttr(err))
	}

	// TODO: we should use a flash message here or something
	http.Redirect(w, r, "/account", http.StatusSeeOther)
}

func (s *idpServer) serveLivez(w http.ResponseWriter, r *http.Request) {
	// TODO(andrew-d): do more checks to make sure that the server is
	// actually healthy; e.g. check if we can do a no-op write to the DB
	// perhaps?
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok\n"))
}

func (s *idpServer) serveReadyz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok\n"))
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
