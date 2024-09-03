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
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-jose/go-jose/v4"
	flag "github.com/spf13/pflag"

	"github.com/andrew-d/homeauth/pwhash"
	"github.com/andrew-d/homeauth/session"
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
}

type idpSession struct {
	Email string
}

func (s *idpServer) httpHandler() http.Handler {
	r := chi.NewRouter()
	// TODO: request logger
	r.Get("/", s.serveIndex)
	r.Get("/.well-known/jwks.json", s.serveJWKS)
	r.Get("/.well-known/openid-configuration", s.serveOpenIDConfiguration)
	r.Get("/userinfo", s.serveUserinfo)
	r.Post("/token", s.serveToken)

	r.Get("/login", s.serveGetLogin)
	r.Post("/login", s.servePostLogin)

	// Authenticated endpoints
	r.Group(func(r chi.Router) {
		r.Use(s.ss.LoadContextWithHandler(http.HandlerFunc(s.redirectToLogin)))

		r.Get("/account", s.serveAccount)
	})

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
}

func (s *idpServer) serveGetLogin(w http.ResponseWriter, r *http.Request) {
	const page = `<html>
	<head></head>
	<body>
		<form action="/login" method="post">
			<input type="text" name="username">
			<input type="password" name="password">
			<input type="submit" value="Login">
		</form>
	</body>
	</html>`
	w.Write([]byte(page))
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
