package main

import (
	"bytes"
	"cmp"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/smtp"
	"net/url"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"text/template"
	"time"

	"crawshaw.dev/jsonfile"
	"github.com/go-chi/chi/v5"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
	"github.com/jordan-wright/email"
	flag "github.com/spf13/pflag"

	"github.com/andrew-d/homeauth/internal/buildtags"
	"github.com/andrew-d/homeauth/internal/db"
	"github.com/andrew-d/homeauth/internal/openidtypes"
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

	db, err := jsonfile.Load[data](*dbPath)
	if errors.Is(err, fs.ErrNotExist) {
		db, err = jsonfile.New[data](*dbPath)
	}
	if err != nil {
		fatal(logger, "failed to open database", "path", *dbPath, errAttr(err))
	}

	hasher := pwhash.New(2, 512*1024, 2)

	idp := &idpServer{
		logger:    logger.With(slog.String("service", "idp")),
		serverURL: *serverURL,
		db:        db,
		hasher:    hasher,
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

type idpServer struct {
	logger         *slog.Logger
	serverURL      string
	serverHostname string
	db             *jsonfile.JSONFile[data]
	hasher         *pwhash.Hasher
}

func (s *idpServer) initializeConfig() error {
	// Parse our server URL to get the hostname.
	u, err := url.Parse(s.serverURL)
	if err != nil {
		// No point in continuing if the server URL is invalid.
		return fmt.Errorf("invalid server URL: %w", err)
	}
	s.serverHostname = u.Hostname()

	// Verify the config in the database.
	var errs []error
	s.db.Read(func(data *data) {
		if e := data.Email; e != nil {
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
	})

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
			"num_clients", len(data.Clients),
		)
		for clientID, client := range data.Clients {
			s.logger.Debug("client",
				"name", client.Name,
				"client_id", clientID,
				"redirect_uris", client.RedirectURIs,
			)
		}

		s.logger.Info("IdP cryptographic keys",
			"primary_signing_key", data.PrimarySigningKeyID,
		)
		if e := data.Email; e != nil {
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
	r := chi.NewRouter()
	r.Use(RequestLogger(s.logger))

	// TODO: Access-Control-Allow-Origin header for certain endpoints

	r.Get("/", s.serveIndex)
	r.Get("/.well-known/jwks.json", s.serveJWKS)
	r.Get("/.well-known/openid-configuration", s.serveOpenIDConfiguration)
	// TODO: webfinger for Tailscale compat?

	// OIDC IdP endpoints
	r.Get("/authorize/public", s.serveAuthorize)
	r.Post("/token", s.serveToken)

	// Per the OIDC spec § 5.3, the "userinfo" endpoint must support GET and POST
	r.Get("/userinfo", s.serveUserinfo)
	r.Post("/userinfo", s.serveUserinfo)

	// TODO: OIDC RP endpoints

	// Login endpoints for this application
	r.Get("/login", s.serveGetLogin)
	r.Post("/login", s.servePostLogin)

	r.Get("/login/check-email", s.serveGetLoginCheckEmail)
	r.Get("/login/magic", s.serveGetMagicLogin)

	// Authenticated endpoints
	r.Group(func(r chi.Router) {
		r.Use(s.requireSession(http.HandlerFunc(s.redirectToLogin)))

		r.Get("/account", s.serveAccount)
		r.Post("/account/logout", s.serveLogout)
		r.Post("/account/logout-other-sessions", s.serveLogoutOtherSessions)
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
		key = data.SigningKeys[data.PrimarySigningKeyID]
	})

	if key != nil {
		keyID, pkey, err = parseRSASigningKey(key)
		if err == nil {
			return
		}

		s.logger.Warn("failed to parse key from database", "keyID", key.ID, errAttr(err))
	}

	err = s.db.Write(func(data *data) error {
		// Re-check the key in case it was created while we were reading.
		key = data.SigningKeys[data.PrimarySigningKeyID]
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
		data.PrimarySigningKeyID = fmt.Sprint(keyID)
		if data.SigningKeys == nil {
			data.SigningKeys = make(map[string]*db.SigningKey)
		}
		data.SigningKeys[data.PrimarySigningKeyID] = &db.SigningKey{
			ID:        data.PrimarySigningKeyID,
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

func (s *idpServer) serveOpenIDConfiguration(w http.ResponseWriter, r *http.Request) {
	// TODO: maybe use a separate endpoint for requests coming from localhost?

	metadata := openidtypes.ProviderMetadata{
		Issuer:                 s.serverURL,
		AuthorizationEndpoint:  s.serverURL + "/authorize/public",
		JWKS_URI:               s.serverURL + "/.well-known/jwks.json",
		UserinfoEndpoint:       s.serverURL + "/userinfo",
		TokenEndpoint:          s.serverURL + "/token",
		ScopesSupported:        []string{"openid", "email"},
		ResponseTypesSupported: []string{"id_token", "code"},
		SubjectTypesSupported:  []string{"public"},
		ClaimsSupported: []string{
			// Claims from the jwt.Claims struct
			"sub",

			// Additional claims supported by this IdP
			"email", // email address
		},
		IDTokenSigningAlgValuesSupported: []string{
			// Per the OpenID spec:
			//	"The algorithm RS256 MUST be included"
			string(jose.RS256),
		},
	}

	w.Header().Set("Content-Type", "application/json")
	jenc := json.NewEncoder(w)
	jenc.SetIndent("", "  ")
	if err := jenc.Encode(metadata); err != nil {
		http.Error(w, "failed to encode metadata", http.StatusInternalServerError)
		return
	}
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

// serveUserinfo serves the OpenID Connect "userinfo" endpoint.
//
// From the OIDC spec § 5.3:
//
//	The UserInfo Endpoint is an OAuth 2.0 Protected Resource that returns
//	Claims about the authenticated End-User. To obtain the requested Claims
//	about the End-User, the Client makes a request to the UserInfo Endpoint
//	using an Access Token obtained through OpenID Connect Authentication.
//	These Claims are normally represented by a JSON object that contains a
//	collection of name and value pairs for the Claims.
func (s *idpServer) serveUserinfo(w http.ResponseWriter, r *http.Request) {
	tokenString, err := getBearerToken(r)
	if err != nil {
		s.logger.Warn("failed to get bearer token", "error", err)
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// Load the access token from the database, along with any user that it references.
	var (
		accessToken *db.AccessToken
		user        *db.User
	)
	s.db.Read(func(data *data) {
		accessToken = data.AccessTokens[tokenString]
		if accessToken != nil {
			user = data.Users[accessToken.UserUUID]
		}
	})

	now := time.Now()
	if accessToken == nil || accessToken.Expiry.Time.Before(now) {
		if accessToken == nil {
			s.logger.Warn("access token not found", "token", tokenString)
		} else {
			s.logger.Warn("access token expired",
				"token", tokenString,
				"expiry", accessToken.Expiry,
				"now", now,
			)
		}

		// Always return the same error if the token is invalid or
		// expired, so as not to leak information.
		http.Error(w, "access token not found", http.StatusUnauthorized)
		return
	}
	// The user should always be found if the access token is valid, but
	// check anyway and return the same error as above if not.
	if user == nil {
		s.logger.Warn("user not found",
			"token", tokenString,
			"user_uuid", user.UUID,
		)
		http.Error(w, "access token not found", http.StatusUnauthorized)
		return
	}

	// Add the user UUID to the request log attributes.
	AddRequestLogAttrs(r, slog.String("user_uuid", user.UUID))

	// Construct the userinfo response
	userinfo := openidtypes.UserInfoResponse{
		Subject:       user.UUID,
		Email:         user.Email,
		EmailVerified: user.EmailVerified,
	}

	w.Header().Set("Content-Type", "application/json")
	jenc := json.NewEncoder(w)
	jenc.SetIndent("", "  ")
	if err := jenc.Encode(userinfo); err != nil {
		s.logger.Error("failed to encode userinfo response", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
}

func (s *idpServer) serveAuthorize(w http.ResponseWriter, r *http.Request) {
	// This endpoint is visited by the user that is being authenticated;
	// they're redirected here by the service they're trying to
	// authenticate to (the "relying party" / RP).

	// First, validate the request, per the OIDC spec § 3.1.2.2
	// ("Authentication Request Validation").

	// "1. The Authorization Server MUST validate all the OAuth 2.0
	// parameters according to the OAuth 2.0 specification."
	//
	// The OAuth 2.0 specification is RFC6749, and § 4.1.1 states that the
	// "response_type" and "client_id" parameters are REQUIRED, the
	// "redirect_uri" parameter is OPTIONAL, the "scope" parameter is
	// OPTIONAL, and the "state" parameter is RECOMMENDED.
	responseType := r.URL.Query().Get("response_type")
	clientID := r.URL.Query().Get("client_id")
	if responseType == "" || clientID == "" {
		http.Error(w, "missing response_type or client_id", http.StatusBadRequest)
		return
	}

	// Per RFC6749 § 3.1.2:
	//
	//	The redirection endpoint URI MUST be an absolute URI as defined
	//	by [RFC3986] Section 4.3.  The endpoint URI MAY include an
	//	"application/x-www-form-urlencoded" formatted (per Appendix B)
	//	query component ([RFC3986] Section 3.4), which MUST be retained
	//	when adding additional query parameters.  The endpoint URI MUST
	//	NOT include a fragment component.
	var redirectURI *url.URL
	if uri := r.URL.Query().Get("redirect_uri"); uri != "" {
		var err error
		redirectURI, err = url.ParseRequestURI(uri)
		if err != nil {
			http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
			return
		}
		if err := validateRedirectURI(redirectURI); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}

	// TODO: should we require the 'state' parameter, to defend against
	// poorly-implemented RPs?
	state := r.URL.Query().Get("state")
	if state == "" {
		s.logger.Warn("missing state parameter in authorization request", "redirect_uri", redirectURI)
	}

	// "2. Verify that a scope parameter is present and contains the openid
	// scope value [...]"
	scopes := strings.Split(r.URL.Query().Get("scope"), " ")
	if !slices.Contains(scopes, "openid") {
		http.Error(w, "missing openid scope", http.StatusBadRequest)
		return
	}

	// "3. The Authorization Server MUST verify that all the REQUIRED
	// parameters are present and their usage conforms to this
	// specification."
	// TODO

	// "4. If the sub (subject) Claim is requested with a specific value
	// for the ID Token, the Authorization Server MUST only send a positive
	// response if the End-User identified by that sub value has an active
	// session with the Authorization Server or has been Authenticated as a
	// result of the request. The Authorization Server MUST NOT reply with
	// an ID Token or Access Token for a different user, even if they have
	// an active session with the Authorization Server. Such a request can
	// be made either using an id_token_hint parameter or by requesting a
	// specific Claim Value as described in Section 5.5.1, if the claims
	// parameter is supported by the implementation."
	//
	// In other words: if the RP requests that we only authorize a specific
	// user, we should verify that the currently-authenticated user
	// matches.
	//
	// We don't set "claims_parameter_supported", so we only need to check
	// for the "id_token_hint" parameter.
	idTokenHint := r.URL.Query().Get("id_token_hint")
	if idTokenHint != "" {
		// "5. When an id_token_hint is present, the OP MUST validate
		// that it was the issuer of the ID Token. The OP SHOULD accept
		// ID Tokens when the RP identified by the ID Token has a
		// current session or had a recent session at the OP, even when
		// the exp time has passed."

		// TODO: implement me
		http.Error(w, "id_token_hint not implemented", http.StatusNotImplemented)
		return
	}

	// Okay, we successfully validated the request parameters. Now, see if
	// we have a user logged in.
	var (
		user   *db.User
		client *db.Client
	)
	s.db.Read(func(data *data) {
		client = data.Clients[clientID]

		session, ok := s.getSession(data, r)
		if ok {
			user, ok = data.Users[session.UserUUID]
			if !ok {
				s.logger.Warn("session refers to non-existent user", "session", session, "user_uuid", session.UserUUID)
			}
		}
	})
	if client == nil {
		s.logger.Warn("client not found", "client_id", clientID)
		http.Error(w, "client not found", http.StatusBadRequest)
		return
	}

	if !slices.Contains(client.RedirectURIs, redirectURI.String()) {
		s.logger.Warn("client not allowed to redirect to URI",
			"client_id", clientID,
			"redirect_uri", redirectURI,
			"allowed_uris", client.RedirectURIs,
		)
		http.Error(w, "client not allowed to redirect to URI", http.StatusBadRequest)
		return
	}

	// Per the OIDC spec § 3.1.2.3:
	//
	//	The Authorization Server MUST NOT interact with the End-User in the following case:
	//
	//	The Authentication Request contains the prompt parameter with
	//	the value none. In this case, the Authorization Server MUST
	//	return an error if an End-User is not already Authenticated or
	//	could not be silently Authenticated.
	prompt := r.URL.Query().Get("prompt")
	if user == nil && prompt == "none" {
		redirectWithError(w, r, redirectURI, "login_required", "user not authenticated", state)
		return
	}
	if prompt == "login" {
		http.Error(w, "prompt=login not implemented", http.StatusNotImplemented)
		return
	}

	// Okay, if we don't have a session, redirect the user to login and
	// return them to this flow after they've done that.
	if user == nil {
		s.logger.Debug("no session; redirecting to login")
		s.redirectToLogin(w, r)
		return
	}

	// Okay, now that we've successfully authenticated a user, we need to
	// figure out what to reply to the RP with. Switch based on the
	// "response_type" parameter.
	//
	// This switch case updates the redirectURI URL to indicate what to
	// redirect to.
	switch responseType {
	case "code":
		code := &db.OAuthCode{
			Code:        randHex(16),
			Expiry:      db.JSONTime{time.Now().Add(time.Minute)},
			ClientID:    clientID,
			UserUUID:    user.UUID,
			RedirectURI: redirectURI.String(),
		}
		s.logger.Info("generated code", "code", code.Code, "user", user.Email)
		if err := s.db.Write(func(data *data) error {
			if data.OAuthCodes == nil {
				data.OAuthCodes = make(map[string]*db.OAuthCode)
			}
			data.OAuthCodes[code.Code] = code
			return nil
		}); err != nil {
			s.logger.Error("failed to save code", errAttr(err))
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		// Redirect the user back to the RP with the code.
		vals := redirectURI.Query()
		vals.Set("code", code.Code)
		if state != "" {
			vals.Set("state", state)
		}
		redirectURI.RawQuery = vals.Encode()

	default:
		http.Error(w, "unsupported response_type", http.StatusNotImplemented)
		return
	}

	http.Redirect(w, r, redirectURI.String(), http.StatusSeeOther)
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
	if ru.Scheme != "http" && ru.Scheme != "https" {
		return fmt.Errorf("redirect_uri must be http or https")
	}
	return nil
}

func (s *idpServer) serveToken(w http.ResponseWriter, r *http.Request) {
	// Double-check that this is a POST request
	if r.Method != http.MethodPost {
		http.Error(w, "invalid method", http.StatusMethodNotAllowed)
		return
	}

	if gt := r.FormValue("grant_type"); gt != "authorization_code" {
		s.logger.Error("unsupported grant type", "grant_type", gt)
		http.Error(w, "unsupported grant type", http.StatusBadRequest)
		return
	}

	codeID := r.FormValue("code")
	if codeID == "" {
		http.Error(w, "missing code", http.StatusBadRequest)
		return
	}

	var (
		code   *db.OAuthCode
		user   *db.User
		client *db.Client
	)
	s.db.Read(func(data *data) {
		code = data.OAuthCodes[codeID]
		if code != nil {
			user = data.Users[code.UserUUID]
			client = data.Clients[code.ClientID]
		}
	})
	if code == nil || user == nil {
		s.logger.Warn("invalid code",
			"code", codeID,
			"code_found", code != nil,
			"user_found", user != nil,
		)
		http.Error(w, "invalid code", http.StatusBadRequest)
		return
	}

	// Ensure that the code hasn't expired
	now := time.Now()
	if now.After(code.Expiry.Time) {
		s.logger.Debug("code expired", "code", code.Code, "expiry", code.Expiry, "now", time.Now())
		http.Error(w, "code expired", http.StatusBadRequest)
		return
	}

	// Per the OIDC spec § 3.1.3.2, "Token Request Validation":
	//
	// "Ensure the Authorization Code was issued to the authenticated Client."
	clientID := r.FormValue("client_id")
	if clientID != code.ClientID {
		s.logger.Warn("client ID mismatch", "client_id", clientID, "expected", code.ClientID)
		http.Error(w, "client ID mismatch", http.StatusBadRequest)
		return
	}

	// Verify that the client secret is correct.
	clientSecret := r.FormValue("client_secret")
	if !secureCompareStrings(clientSecret, client.ClientSecret) {
		s.logger.Warn("client secret mismatch",
			"client_id", clientID,
			"client_secret", clientSecret,
			"expected", client.ClientSecret,
		)
		http.Error(w, "client secret mismatch", http.StatusBadRequest)
		return
	}

	// "Verify that the Authorization Code is valid"; we did this above
	// when we fetched the token from the database.

	// "if possible, verify that the Authorization Code has not been
	// previously used"
	//
	// We do this by deleting the code from the database after it's used,
	// but giving ourselves a short grace period in case there's a network
	// issue or the user refreshes at an inopportune time.
	//
	// We do this when creating an access token, below.

	// "Ensure that the redirect_uri parameter value is identical to the
	// redirect_uri parameter value that was included in the initial
	// Authorization Request."
	providedRedirectURI := r.FormValue("redirect_uri")
	if providedRedirectURI == "" {
		// "If the redirect_uri parameter value is not present when
		// there is only one registered redirect_uri value, the
		// Authorization Server MAY return an error (since the Client
		// should have included the parameter) or MAY proceed without
		// an error (since OAuth 2.0 permits the parameter to be
		// omitted in this case)."
		//
		// TODO: check the client's redirect URIs
		http.Error(w, "missing redirect_uri", http.StatusNotImplemented)
	} else if code.RedirectURI != providedRedirectURI {
		s.logger.Warn("redirect URI mismatch",
			"provided_redirect_uri", providedRedirectURI,
			"redirect_uri", code.RedirectURI,
		)
		http.Error(w, "redirect URI mismatch", http.StatusBadRequest)
		return
	}

	// TODO: "Verify that the Authorization Code used was issued in
	// response to an OpenID Connect Authentication Request (so that an ID
	// Token will be returned from the Token Endpoint)."

	// Construct the claims that we're signing for this response, per the
	claims := openidtypes.Claims{
		Claims: jwt.Claims{
			// jti: TODO: is this required?
			ID: randHex(32),

			// "iss: REQUIRED. Issuer Identifier for the Issuer of the
			// response. The iss value is a case-sensitive URL using the
			// https scheme that contains scheme, host, and optionally,
			// port number and path components and no query or fragment
			// components."
			Issuer: s.serverURL,

			// "sub: REQUIRED. Subject Identifier. A locally unique and
			// never reassigned identifier within the Issuer for the
			// End-User, which is intended to be consumed by the Client,
			// e.g., 24400320 or AItOawmwtWwcT0k51BayewNvutrJUqsvl6qs7A4.
			//
			// It MUST NOT exceed 255 ASCII [RFC20] characters in length.
			// The sub value is a case-sensitive string."
			Subject: user.UUID,

			// "aud: REQUIRED. Audience(s) that this ID Token is intended
			// for. It MUST contain the OAuth 2.0 client_id of the Relying
			// Party as an audience value. It MAY also contain identifiers
			// for other audiences. In the general case, the aud value is
			// an array of case-sensitive strings. In the common special
			// case when there is one audience, the aud value MAY be a
			// single case-sensitive string."
			Audience: jwt.Audience{clientID},

			// "exp: REQUIRED. Expiration time on or after which the ID
			// Token MUST NOT be accepted by the RP when performing
			// authentication with the OP.
			//
			// NOTE: The ID Token expiration time is unrelated the lifetime
			// of the authenticated session between the RP and the OP."
			Expiry: jwt.NewNumericDate(now.Add(5 * time.Minute)),

			// "iat: REQUIRED. Time at which the JWT was issued. Its value
			// is a JSON number representing the number of seconds from
			// 1970-01-01T00:00:00Z as measured in UTC until the
			// date/time."
			IssuedAt: jwt.NewNumericDate(now),

			// "nbf: TODO"
			NotBefore: jwt.NewNumericDate(now.Add(-10 * time.Second)), // grace period for clock skew
		},

		// "nonce: String value used to associate a Client session with an ID
		// Token, and to mitigate replay attacks. The value is passed
		// through unmodified from the Authentication Request to the ID
		// Token. [...] If present in the Authentication Request,
		// Authorization Servers MUST include a nonce Claim in the ID
		// Token with the Claim Value being the nonce value sent in the
		// Authentication Request. Authorization Servers SHOULD perform
		// no other processing on nonce values used. The nonce value is
		// a case-sensitive string."
		Nonce: r.FormValue("nonce"),

		// "email: End-User's preferred e-mail address. Its value MUST
		// conform to the RFC 5322 [RFC5322] addr-spec syntax. The RP
		// MUST NOT rely upon this value being unique, as discussed in
		// Section 5.7"
		Email: user.Email,

		// "email_verified: True if the End-User's e-mail address has
		// been verified; otherwise false. When this Claim Value is
		// true, this means that the OP took affirmative steps to
		// ensure that this e-mail address was controlled by the
		// End-User at the time the verification was performed."
		EmailVerified: user.EmailVerified,

		// TODO: check auth_time?
	}

	signer, err := s.getJOSESigner()
	if err != nil {
		s.logger.Error("failed to get JOSE signer", errAttr(err))
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	// Sign the claims with our private key.
	idToken, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		s.logger.Error("failed to sign token", errAttr(err))
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Now, generate an access token, which is entirely different from the
	// ID token and can just be a random string that we store for later
	// use. Store it in our database for later use.
	at := &db.AccessToken{
		Token:    randHex(32),
		Expiry:   db.JSONTime{now.Add(5 * time.Minute)},
		UserUUID: user.UUID,
	}
	s.db.Write(func(data *data) error {
		if data.AccessTokens == nil {
			data.AccessTokens = make(map[string]*db.AccessToken)
		}
		data.AccessTokens[at.Token] = at

		// Remove the now-used code from the database.
		//
		// NOTE: only do this after we've done all the work required
		// and won't error out.
		delete(data.OAuthCodes, codeID)
		return nil
	})

	// Construct the actual response, per the OIDC spec § 3.1.3.3.
	resp := openidtypes.TokenResponse{
		// "The OAuth 2.0 token_type response parameter value MUST be
		// Bearer [...]"
		TokenType: "Bearer",

		// "In addition to the response parameters specified by OAuth
		// 2.0, the following parameters MUST be included in the
		// response:
		//
		//    id_token   ID Token value associated with the
		//               authenticated session."
		IDToken: idToken,

		// The actual token values.
		AccessToken: at.Token,
		ExpiresIn:   5 * 60, // 5 minutes
		// TODO: refresh token?
	}

	w.Header().Set("Content-Type", "application/json")

	// From the OIDC spec § 3.1.3.3:
	//
	//	All Token Responses that contain tokens, secrets, or other
	//	sensitive information MUST include the following HTTP response
	//	header fields and values:
	w.Header().Set("Cache-Control", "no-store")

	if err := json.NewEncoder(w).Encode(resp); err != nil {
		s.logger.Error("failed to encode token response", errAttr(err))
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (s *idpServer) serveGetLogin(w http.ResponseWriter, r *http.Request) {
	// TODO: verify the 'next' parameter is a valid URL?

	if err := templates.All().ExecuteTemplate(w, "login.html.tmpl", map[string]any{
		"Next": r.URL.Query().Get("next"),
	}); err != nil {
		s.logger.Error("failed to render login template", errAttr(err))
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}

func (s *idpServer) serveGetLoginCheckEmail(w http.ResponseWriter, r *http.Request) {
	if err := templates.All().ExecuteTemplate(w, "login-email.html.tmpl", nil); err != nil {
		s.logger.Error("failed to render login-email template", errAttr(err))
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}

func (s *idpServer) servePostLogin(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")

	// Load the user by their email address.
	var user *db.User
	s.db.Read(func(data *data) {
		// This is slow but fine for now since we don't have many users.
		for _, u := range data.Users {
			if u.Email == username {
				user = u
				return
			}
		}
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

func (s *idpServer) getNextURL(r *http.Request) string {
	// Redirect the user to the 'next' parameter, or the account page if
	// there's none provided or it's invalid.
	var nextURL string = "/account"
	if next := r.FormValue("next"); next != "" {
		// Validate that the URL is relative and not an open redirect.
		if u, err := url.Parse(next); err == nil && !u.IsAbs() {
			nextURL = next
		} else {
			s.logger.Warn("invalid next URL", "next", next, errAttr(err), "is_abs", u.IsAbs())
		}
	}
	return nextURL
}

func (s *idpServer) servePostLoginPassword(w http.ResponseWriter, r *http.Request, user *db.User) {
	password := r.FormValue("password")
	if !s.hasher.Verify([]byte(password), []byte(user.PasswordHash)) {
		s.logger.Info("invalid password for user", "username", user.Email)
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	// Log the user in by creating a session.
	session := &db.Session{
		UserUUID: user.UUID,
		Expiry:   db.JSONTime{time.Now().Add(7 * 24 * time.Hour)},
	}
	if err := s.putSession(w, r, session); err != nil {
		// callee has already logged
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	s.logger.Info("logged in user",
		"username", user.Email,
		"user_uuid", user.UUID,
		"session_id", session.ID,
	)

	http.Redirect(w, r, s.getNextURL(r), http.StatusSeeOther)
}

func (s *idpServer) servePostLoginEmail(w http.ResponseWriter, r *http.Request, user *db.User) {
	// Generate a magic login link for this user.
	magic := &db.MagicLoginLink{
		Token:    randHex(64),
		UserUUID: user.UUID,
		Expiry:   db.JSONTime{time.Now().Add(10 * time.Minute)},
		NextURL:  s.getNextURL(r),
	}

	var emailConfig *EmailConfig
	if err := s.db.Write(func(data *data) error {
		emailConfig = data.Email
		if data.MagicLinks == nil {
			data.MagicLinks = make(map[string]*db.MagicLoginLink)
		}
		data.MagicLinks[magic.Token] = magic
		return nil
	}); err != nil {
		s.logger.Error("failed to save magic login", errAttr(err))
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	magicURL := s.serverURL + "/login/magic?token=" + magic.Token
	if buildtags.IsDev {
		s.logger.Info("generated magic login link",
			"user_uuid", user.UUID,
			"url", magicURL,
		)
	}

	fromAddr := cmp.Or(emailConfig.FromAddress, emailConfig.SMTPUsername)
	subject := fmt.Sprintf("Login to homeauth (%s)", s.serverHostname)

	// Send the user an email
	e := &email.Email{
		To:      []string{user.Email},
		From:    fmt.Sprintf("homeauth <%s>", fromAddr),
		Subject: cmp.Or(emailConfig.Subject, subject),
		Text:    []byte("Use this link to log in: " + magicURL),
		HTML:    makeEmailBody(magicURL),
	}

	// Split the host and port from the address; we know this never fails
	// because initializeConfig checked.
	host, _, _ := net.SplitHostPort(emailConfig.SMTPServer)
	auth := smtp.PlainAuth(
		emailConfig.FromAddress,  // identity
		emailConfig.SMTPUsername, // user
		emailConfig.SMTPPassword, // password
		host,                     // host
	)

	// Use TLS if either explicitly set or no TLS options are set.
	var err error
	if emailConfig.useTLS() {
		err = e.SendWithTLS(emailConfig.SMTPServer, auth, &tls.Config{
			ServerName: host,
		})
	} else if emailConfig.useStartTLS() {
		err = e.SendWithStartTLS(emailConfig.SMTPServer, auth, &tls.Config{
			ServerName: host,
		})
	} else {
		// No TLS; TODO: should we disable this?
		err = e.Send(emailConfig.SMTPServer, auth)
	}

	if err != nil {
		s.logger.Error("failed to send email", errAttr(err))
		http.Error(w, "internal server error; failed to send email", http.StatusInternalServerError)
		return
	}

	// Redirect the user to a landing page that says "check your email"
	http.Redirect(w, r, "/login/check-email", http.StatusSeeOther)
}

// emailBodyTemplate is an HTML template for the email body we send to users
// for them to log in. Most email clients have a fairly restrictive set of
// allowed formatting for emails, so we keep this simple.
//
// TODO: make this look a bit nicer
var emailBodyTemplate = template.Must(template.New("email").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>homeauth login</title>
</head>
<body>
<p>Use this link to log in:</p>
<p><a href="{{ .MagicURL }}">click here</a></p>
</body>
</html>`))

func makeEmailBody(magicURL string) []byte {
	var buf bytes.Buffer
	if err := emailBodyTemplate.Execute(&buf, map[string]any{
		"MagicURL": magicURL,
	}); err != nil {
		panic(fmt.Sprintf("failed to execute email body template: %v", err))
	}
	return buf.Bytes()
}

func (s *idpServer) serveGetMagicLogin(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "missing token", http.StatusBadRequest)
		return
	}

	// TODO; there's a race here where multiple uses of the same magic link
	// can happen at once; need to fix that.
	var (
		magic *db.MagicLoginLink
		user  *db.User
	)
	s.db.Read(func(data *data) {
		magic = data.MagicLinks[token]
		if magic != nil {
			user = data.Users[magic.UserUUID]
		}
	})
	if magic == nil {
		s.logger.Warn("no such magic login", "token", token)
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}
	if user == nil {
		s.logger.Error("no such user for magic login", "token", token, "user_uuid", magic.UserUUID)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	// Check that the token hasn't expired.
	if time.Now().After(magic.Expiry.Time) {
		s.logger.Warn("magic login expired", "token", token, "expiry", magic.Expiry, "now", time.Now())
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}

	// Log the user in by creating a session.
	session := &db.Session{
		UserUUID: user.UUID,
		Expiry:   db.JSONTime{time.Now().Add(7 * 24 * time.Hour)},
	}
	if err := s.putSession(w, r, session); err != nil {
		// callee has already logged
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if err := s.db.Write(func(data *data) error {
		// Remove the magic login link from the database, now that it's
		// been used; TODO see above with a race
		delete(data.MagicLinks, token)

		// Update this user's EmailVerified field; now that they've
		// logged in via an email link, we know they control that email
		// address.
		data.Users[user.UUID].EmailVerified = true
		return nil
	}); err != nil {
		s.logger.Error("failed to update database after login", errAttr(err))
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	s.logger.Info("logged in user via magic link",
		"user_uuid", magic.UserUUID,
		"session_id", session.ID,
		"next_url", magic.NextURL,
	)

	// Redirect the user to the account page.
	if magic.NextURL != "" {
		http.Redirect(w, r, magic.NextURL, http.StatusSeeOther)
	} else {
		http.Redirect(w, r, "/account", http.StatusSeeOther)
	}
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
	user := s.mustUserFromContext(r.Context())

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
		"User":        user,
		"NumSessions": numSessions,
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

	// Delete all sessions for the current user.
	s.db.Write(func(data *data) error {
		for _, session := range data.Sessions {
			if session.UserUUID != currSession.UserUUID {
				continue
			}
			delete(data.Sessions, session.ID)
		}
		return nil
	})

	// Set an empty session cookie as well
	// TODO: this doesn't work; we end up sending a header on login like
	// `session=; session=...` which doesn't work. Removing the session
	// above is enough for now.
	//s.clearSession(w, r)

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
		return nil
	})

	// TODO: we should use a flash message here or something
	http.Redirect(w, r, "/account", http.StatusSeeOther)
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
