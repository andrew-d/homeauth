// csrf provides middleware to protect from CSRF attacks.
//
// This package provides a simple and fast solution using the "double-submit
// cookie" pattern: A secret token is sent to the user's browser in a cookie.
// The same token is also written to any HTML forms presented on the website.
// Any POST (todo: and others?) requests must include this token in the form
// data, and it must match the value in the cookie. This prevents CSRF attacks
// because attackers would have no way of knowing the CSRF cookie value for
// their victim.
//
// This package implements the pattern using a separate cookie for the CSRF
// token, so it does not require a user session for forms to be protected. This
// means the login form can also be protected, without needing to have sessions
// for logged-out users — which could be quite costly. This way, logged out
// users can remain "stateless" (from a sessions point of view) and not require
// any writes to the "database".
//
// To make use of it, use the [Middleware] on any paths that require CSRF
// protection, and any paths that need to be sure to set the CSRF token:
//
//	r.Group(func(r chi.Router) {
//		r.Use(csrf.Middleware(true))
//		r.Get("/", serveIndex)
//		r.Get("/someForm", serveForm)
//		r.Post("/doSomething", servePostSomething)
//	}
//
// All POST (todo: etc) paths in your app that take requests from a browser (from
// forms or from JavaScript) should include this middleware. All pages that
// display an HTML form, or contain JavaScript that needs to make XHR requests
// to protected pages should also include it. The middleware will take care of
// both setting the CSRF cookie, and validating submitted CSRF tokens on POST
// (todo: etc) requests.
//
// Because it is very fast and stateless it is easiest to include this
// middleware on all paths that a browser will hit. Omit the middleware on
// endpoints that won't be hit by browser user-agents, such as APIs exclusively
// used by API clients:
//
//	// Routes that require CSRF protection
//	r.Group(func(r chi.Router) {
//		r.Use(csrf.Middleware(true))
//		r.Get("/", serveIndex)
//		r.Get("/someForm", serveForm)
//		r.Post("/doSomething", servePostSomething)
//	}
//
//	// Routes that *don't* require CSRF protection
//	r.Group(func(r chi.Router) {
//		r.Get("/.well-known/host-meta.json", serveHostMeta)
//		r.Get("/userinfo", serveUserInfo)
//		r.Post("/userinfo", serveUserInfo)
//	}
//
// Forms submitting to protected endpoints will need to include a token for verification. The form field containing the token must be named as per [FormField], and a token to include as its value can be retrieved from the [http.Request] using [GetToken]:
//
// Go:
//
//	s.templates.ExecuteTemplate(w, "login.html.tmpl", map[string]any{
//	  "csrfTokenField": csrf.FormField,
//	  "csrfTokenValue": csrf.GetToken(r),
//	})
//
// Template:
//
//	<input type="hidden" name="{{ .csrfTokenField }}" value="{{ .csrfTokenValue }}">
//
// For JavaScript that needs to submit via XHR, the CSRF token can be stored in a meta tag on the page for retrieval via the JavaScript. TODO: how should JS submit it? :
//
// Go:
//
//	s.templates.ExecuteTemplate(w, "foo.html.tmpl", map[string]any{
//	  "CSRFToken": csrf.GetToken(r),
//	})
//
// Template:
//
//	{{- with .CSRFToken }}
//	<meta name="csrf-token" content="{{ . }}">
//	{{- end }}
package csrf

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"time"
)

// key is an unexported type for storing/retrieving CSRF tokens in a context.
//
// This prevents collisions with keys defined in other packages.
type key int

// tokenKey is the key for token values in Contexts.
//
// Not exported: clients should use [GetToken] to retrieve a token from a
// request's context, and rely on the [SetCookieMiddleware] for setting them.
var tokenKey key

// token is the type for a CSRF token. Stored and manipulated internally as a
// byte array, we encode/decode to/from strings as necessary.
type token []byte

// cookieName is not exported as no clients should be accessing the cookie
// directly. Instead use the middleware to set/get/check this value.
const cookieName = "X-CSRF-Protect"

// tokenLength is the length in bytes of the CSRF tokens to generate. 16 bytes = 128 bits.
const tokenLength = 16

// FormField is the name of the field we look in form submissions for the
// submitted token. Exported because clients need to know this to render HTML.
//
// Go:
//
//	s.templates.ExecuteTemplate(w, "login.html.tmpl", map[string]any{
//	  "csrfTokenField": csrf.FormField,
//	  "csrfTokenValue": csrf.GetToken(r),
//	})
//
// Template:
//
//	<input type="hidden" name="{{ .csrfTokenField }}" value="{{ .csrfTokenValue }}">
const FormField = "CSRF-Token"

// Middleware provides an http.Handler to use as middleware that does two
// things:
//
//  1. It generates random CSRF tokens and sets them in cookies in responses
//  2. It validates that any POST (todo: etc) requests include this cookie and a
//     matching CSRF token in the form data (todo: JS)
//
// By using this middleware, all endpoints behind it will be protected against
// CSRF attacks as long as:
//
//   - Only POST (todo: etc) requests modify data, and GET (todo: etc) requests do not
//   - The CSRF tokens remain undiscoverable by attackers (no XSS, no MITM, no other leaks)
//
// This middleware stores all state necessary in the one cookie it sets. It does
// not require sessions and does not behave any differently for logged-in vs
// logged-out users.
//
// Example:
//
//	r.Use(csrf.Middleware(true))
//
// TODO: document secure option
func Middleware(secure bool) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// First ensure that we have a CSRF token cookie

			token := getTokenFromCookie(r)

			// If there was no token in a cookie, create a new one
			if token == nil {
				var err error
				token, err = newToken()
				if err != nil {
					http.Error(w, "Nope", http.StatusBadRequest)
					return
				}
			}

			// Always set a CSRF cookie whether it's new or not, to ensure it stays alive
			setTokenCookie(w, token, secure)

			// Store token in request context so it's immediately available for
			// rendering the token in forms etc (see GetToken)
			r = requestWithToken(r, token)

			// Second, if this is a data-modifying request, only permit it if we have
			// a valid CSRF token submission
			if r.Method == http.MethodPost { // TODO: check which methods are safe
				formToken := decodeToken(r.FormValue(FormField)) // TODO: what about JavaScript?

				if !validateToken(token, formToken) {
					http.Error(w, "Nopeity", http.StatusBadRequest) // TODO: better error page. Also JSON errors for JS.
					return
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

// newToken generates a new, random CSRF token. Tokens are generated using the
// best CSPRNG available on the platform (see [crypto/rand]).
func newToken() (token, error) { // TODO: should this panic on failure rather than return an error? When could this reasonably error?
	bytes := make([]byte, tokenLength)
	_, err := rand.Read(bytes)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

// getTokenFromCookie retrieves the CSRF token from the cookie named
// [cookieName], or nil if not found. Returns nil if the cookie is not set or
// any error occurs decoding the token in the cookie.
func getTokenFromCookie(r *http.Request) token {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return nil
	}
	encodedToken := c.Value
	return decodeToken(encodedToken)
}

// setTokenCookie sets the supplied token to a cookie (named [cookieName]). The
// token can be retrieved via [getTokenFromCookie].
func setTokenCookie(w http.ResponseWriter, token token, secure bool) {
	encodedToken := base64.RawURLEncoding.EncodeToString(token)

	cookie := http.Cookie{
		Name:     cookieName,
		Value:    encodedToken,
		Expires:  time.Now().Add(365 * 24 * time.Hour), // TODO: can this be infinite? Can we set relative to avoid clock errors?
		Secure:   secure,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode, // TODO: what happens if a new request comes in without a cookie due to this. Will it trample the existing value and break other tabs that are open?
	}
	http.SetCookie(w, &cookie)
}

// requestWithToken returns a new [http.Request] with the token stored in the
// request's context. This can be retrieved with [GetToken] for use in e.g. HTML
// forms.
func requestWithToken(r *http.Request, token token) *http.Request {
	c := r.Context()
	c = context.WithValue(c, tokenKey, token)
	return r.WithContext(c)
}

// GetToken returns a CSRF token for adding to HTML forms and (TODO) XHR.
//
// See also [FormField] for the name to use for the CSRF field in HTML forms.
//
// Example:
//
// Go:
//
//	s.templates.ExecuteTemplate(w, "login.html.tmpl", map[string]any{
//	  "csrfTokenField": csrf.FormField,
//	  "csrfTokenValue": csrf.GetToken(r),
//	})
//
// Template:
//
//	<input type="hidden" name="{{ .csrfTokenField }}" value="{{ .csrfTokenValue }}">
func GetToken(r *http.Request) string {
	c := r.Context()
	t, _ := c.Value(tokenKey).(token)
	return stringifyToken(t)
}

// validateToken checks if the cookie token and the token sent in a form/XHR
// request are both present and match. Returns true if they match and false if
// they do not. Returns false if either token is nil. Uses a constant-time
// comparison internally, to be safe against timing attacks.
func validateToken(cookieToken token, requestToken token) bool {
	if cookieToken == nil || requestToken == nil {
		return false
	}

	// ConstantTimeCompare returns 1 if the two slices are equal
	if subtle.ConstantTimeCompare(cookieToken, requestToken) == 1 {
		return true
	} else {
		return false
	}
}

// decodeToken decodes the string representation of a token into a token.
// Returns nil if any decoding error occurs, or if the supplied string is nil.
func decodeToken(enc string) token {
	token, err := base64.RawURLEncoding.DecodeString(enc)
	if err != nil {
		return nil
	}
	return token
}

// stringifyToken encodes a token to a URL-safe, HTML-safe, ASCII-safe string
// representation. Returns nil if the supplied token is nil.
func stringifyToken(t token) string {
	return base64.RawURLEncoding.EncodeToString(t)
}
