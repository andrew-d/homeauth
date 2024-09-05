package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	flag "github.com/spf13/pflag"

	"github.com/andrew-d/homeauth/pwhash"
	"github.com/andrew-d/homeauth/session"
	"github.com/andrew-d/homeauth/static"
)

var (
	port      = flag.IntP("port", "p", 8080, "Port to listen on")
	serverURL = flag.String("server-url", fmt.Sprintf("http://localhost:%d", *port), "Public URL of the server")
	db        = flag.String("db", "homeauth.json", "Path to the database file")
)

func main() {
	flag.Parse()
	logger := slog.Default()

	db, err := NewDB(*db)
	if err != nil {
		fatal(logger, "failed to open database", "path", *db, errAttr(err))
	}
	defer db.Close()

	hasher := pwhash.New(2, 512*1024, 2)

	ss := session.New[*idpSession]("homeauth", 7*24*time.Hour)
	idp := &idpServer{
		logger:    logger.With(slog.String("service", "idp")),
		serverURL: *serverURL,
		ss:        ss,
		db:        db,
		hasher:    hasher,
	}

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
	logger    *slog.Logger
	serverURL string
	ss        *session.Store[*idpSession]
	db        *DB
	hasher    *pwhash.Hasher

	signingKeyOnce sync.Once
	signingKey     *rsa.PrivateKey
	signingKeyID   uint64
	signer         jose.Signer
}

type idpSession struct {
	Email string
}

func (s *idpServer) httpHandler() http.Handler {
	r := chi.NewRouter()
	// TODO: request logger middleware

	r.Get("/", s.serveIndex)
	r.Get("/.well-known/jwks.json", s.serveJWKS)
	r.Get("/.well-known/openid-configuration", s.serveOpenIDConfiguration)
	// TODO: webfinger for Tailscale compat?

	// OIDC IdP endpoints
	r.Get("/authorize/public", s.serveAuthorize)
	r.Post("/token", s.serveToken)
	r.Get("/userinfo", s.serveUserinfo)

	// TODO: OIDC RP endpoints

	// Login endpoints for this application
	r.Get("/login", s.serveGetLogin)
	r.Post("/login", s.servePostLogin)

	// Authenticated endpoints
	r.Group(func(r chi.Router) {
		r.Use(s.ss.LoadContextWithHandler(http.HandlerFunc(s.redirectToLogin)))

		r.Get("/account", s.serveAccount)
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
		io.WriteString(w, "<html><body><h1>IDP Home</h1></body></html>")
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

func (s *idpServer) getJWKS() (keyID uint64, pkey *rsa.PrivateKey, err error) {
	// TODO: persist key to disk and load here
	// TODO: generate ECDSA or Ed25519 keys here as well?

	s.signingKeyOnce.Do(func() {
		s.logger.Info("generating new RSA key")
		s.signingKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			s.logger.Error("failed to generate RSA key", errAttr(err))
			return
		}

		// Get a non-zero uint64 for the key ID.
		var buf [8]byte
		for {
			rand.Read(buf[:]) // never actually errors
			s.signingKeyID = binary.BigEndian.Uint64(buf[:])
			if s.signingKeyID != 0 {
				break
			}
		}

		s.logger.Info("generated new RSA key", "keyID", s.signingKeyID)

		s.signer, err = jose.NewSigner(jose.SigningKey{
			Algorithm: jose.RS256,
			Key:       s.signingKey,
		}, &jose.SignerOptions{
			EmbedJWK: false,
			ExtraHeaders: map[jose.HeaderKey]any{
				jose.HeaderType: "JWT",
				"kid":           fmt.Sprint(s.signingKeyID),
			},
		})
		if err != nil {
			s.logger.Error("failed to create signer", errAttr(err))
			return
		}
	})
	return s.signingKeyID, s.signingKey, err
}

func (s *idpServer) serveOpenIDConfiguration(w http.ResponseWriter, r *http.Request) {
	// TODO: maybe use a separate endpoint for requests coming from localhost?

	metadata := OpenIDProviderMetadata{
		Issuer:                 s.serverURL,
		AuthorizationEndpoint:  s.serverURL + "/authorize/public",
		JWKS_URI:               s.serverURL + "/.well-known/jwks.json",
		UserinfoEndpoint:       s.serverURL + "/userinfo",
		TokenEndpoint:          s.serverURL + "/token",
		ScopesSupported:        []string{"openid", "email"},
		ResponseTypesSupported: []string{"id_token", "code"},
		SubjectTypesSupported:  []string{"public"},
		ClaimsSupported:        []string{"sub", "email"},
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

func (s *idpServer) serveUserinfo(w http.ResponseWriter, r *http.Request) {
	// TODO
	http.Error(w, "not implemented", http.StatusNotImplemented)
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
	// we have an active session.
	session, ok := s.ss.Get(r)

	// Per the OIDC spec § 3.1.2.3:
	//
	//	The Authorization Server MUST NOT interact with the End-User in the following case:
	//
	//	The Authentication Request contains the prompt parameter with
	//	the value none. In this case, the Authorization Server MUST
	//	return an error if an End-User is not already Authenticated or
	//	could not be silently Authenticated.
	prompt := r.URL.Query().Get("prompt")
	if !ok && prompt == "none" {
		redirectWithError(w, r, redirectURI, "login_required", "user not authenticated", state)
		return
	}
	if prompt == "login" {
		http.Error(w, "prompt=login not implemented", http.StatusNotImplemented)
		return
	}

	// Okay, if we don't have a session, redirect the user to login and
	// return them to this flow after they've done that.
	if !ok {
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
		code := randHex(16)
		// TODO: store code in DB
		s.logger.Info("generated code", "code", code, "user", session.Email)

		// Redirect the user back to the RP with the code.
		vals := redirectURI.Query()
		vals.Set("code", code)
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

	code := r.FormValue("code")
	if code == "" {
		http.Error(w, "missing code", http.StatusBadRequest)
		return
	}

	// TODO: load the code from our DB somewhere
	// TODO: verify the code hasn't expired
	// TODO: verify that the relying party is allowed to make this request
	// TODO: verify that the redirect URI matches the one used in the auth request

	// Construct the claims that we're signing for this response.
	now := time.Now()
	claims := jwt.Claims{
		ID:        randHex(32),
		Issuer:    s.serverURL,
		Subject:   "TODO",
		IssuedAt:  jwt.NewNumericDate(now),
		NotBefore: jwt.NewNumericDate(now.Add(-10 * time.Second)), // grace period for clock skew
		Expiry:    jwt.NewNumericDate(now.Add(5 * time.Minute)),
		Audience:  jwt.Audience{"TODO-client-id-here"},
	}

	s.getJWKS() // TODO: using for side effect, which I don't love
	signer := s.signer

	// Sign the claims with our private key.
	token, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		s.logger.Error("failed to sign token", errAttr(err))
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	at := randHex(32)
	resp := OpenIDTokenResponse{
		IDToken:     token,
		AccessToken: at,
		TokenType:   "Bearer",
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

var loginTemplate = template.Must(template.New("login").Parse(`<html>
	<head></head>
	<body>
		<form action="/login?next={{.Next}}" method="POST">
			<input type="text" name="username" placeholder="username">
			<input type="password" name="password">
			<input type="submit" value="Login">
		</form>
	</body>
	</html>
`))

func (s *idpServer) serveGetLogin(w http.ResponseWriter, r *http.Request) {
	if err := loginTemplate.Execute(w, map[string]any{
		"Next": r.URL.Query().Get("next"),
	}); err != nil {
		s.logger.Error("failed to render login template", errAttr(err))
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}

func (s *idpServer) servePostLogin(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	// Load the user's password hash
	user, err := s.db.GetUser(username)
	if err != nil {
		s.logger.Info("error getting user", "username", username)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	} else if user == nil {
		s.logger.Info("no such user", "username", username)
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	if !s.hasher.Verify([]byte(password), []byte(user.PasswordHash)) {
		s.logger.Info("invalid password for user", "username", username)
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	// Log the user in by creating a session.
	session := &idpSession{
		Email: user.Email,
	}
	s.ss.Put(w, r, session)

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

	http.Redirect(w, r, nextURL, http.StatusSeeOther)
}

func (s *idpServer) addUser(email, password string) error {
	hash := s.hasher.HashString(password)
	return s.db.PutUser(&DBUser{
		Email:        email,
		PasswordHash: hash,
	})
}

func (s *idpServer) serveAccount(w http.ResponseWriter, r *http.Request) {
	session := s.ss.MustFromContext(r.Context())

	fmt.Fprintf(w, "<html><body><h1>Welcome, %s!</h1></body></html>", template.HTMLEscapeString(session.Email))
}

func randHex(n int) string {
	buf := make([]byte, n)
	rand.Read(buf)
	return fmt.Sprintf("%x", buf)
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
