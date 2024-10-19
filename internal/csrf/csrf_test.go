package csrf

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

type spyHandler struct {
	Called bool
}

func (p *spyHandler) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	fmt.Fprint(w, "Hello, world")
	p.Called = true
}

// TestSetsCookieIfNotSet checks that if a csrf cookie is not already set, we
// set one.
func TestMiddlewareSetsCookieIfNotSet(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	handler := Middleware(false)(&spyHandler{})
	handler.ServeHTTP(w, r)

	response := w.Result()
	cookie := getCookie(response)
	if cookie == nil {
		t.Errorf("No cookie named %q found in response, want one", cookieName)
	}
}

// TestSetsSameCookieIfSet checks two things when the cookie is already set and
// sent in a request. That we still set it even though it's already set: this
// helps ensure it doesn't expire. And that we set it to the same value that is
// already set. Together these ensure the app still works nicely over time, if
// multiple tabs are open, or the back button is used.
func TestMiddlewareSetsSameCookieIfSet(t *testing.T) {
	const want = "bGF1bmRyeSBhbmQgdGF4ZXM"
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: "homeauth_csrf", Value: want})
	w := httptest.NewRecorder()

	handler := Middleware(false)(&spyHandler{})
	handler.ServeHTTP(w, r)

	response := w.Result()
	cookie := getCookie(response)
	if cookie == nil {
		t.Fatalf("No cookie named %q found in response, want one", cookieName)
	}

	if cookie.Value != want {
		t.Errorf("Cookie %q value: got %q, want %q", cookieName, cookie.Value, want)
	}
}

// TestCookiesAreRandom tests (badly) that CSRF tokens are random, by way of
// checking that if we get multiple tokens they are all different.
func TestMiddlewareCookiesAreRandom(t *testing.T) {
	seen := make(map[string]bool)

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	handler := Middleware(false)(&spyHandler{})

	for range 10 {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		response := w.Result()
		cookie := getCookie(response)

		if cookie == nil {
			t.Fatalf("No cookie named %q found in response, want one", cookieName)
		}
		if seen[cookie.Value] {
			t.Fatalf("Got cookie value %q more than once, want a different cookie each time", cookie.Value)
		}
		seen[cookie.Value] = true
	}
}

// TestBlocksUnknownMethods checks that anything other than a GET / POST is
// rejected. This saves us from thinking too hard about what the rules should be
// for those methods, as we aren't actually using them anywhere.
func TestMiddlewareBlocksUnknownMethods(t *testing.T) {
	methods := []string{
		http.MethodHead, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodConnect, http.MethodOptions, http.MethodTrace,
	}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			r := httptest.NewRequest(method, "/", nil)
			w := httptest.NewRecorder()
			spy := spyHandler{}

			handler := Middleware(false)(&spy)
			handler.ServeHTTP(w, r)

			response := w.Result()

			if response.StatusCode != http.StatusMethodNotAllowed {
				t.Errorf("Got status code %d, want %d", response.StatusCode, http.StatusMethodNotAllowed)
			}

			if spy.Called {
				t.Errorf("Request got permitted by middleware, want it to be denied")
			}
		})
	}
}

// TestBlocksUnknownMethods checks that POST requests are blocked if no token is
// sent in the request.
func TestMiddlewareBlocksPostWithoutToken(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()
	spy := spyHandler{}

	handler := Middleware(false)(&spy)
	handler.ServeHTTP(w, r)

	response := w.Result()

	if response.StatusCode != http.StatusBadRequest {
		t.Errorf("Got status code %d, want %d", response.StatusCode, http.StatusBadRequest)
	}

	if spy.Called {
		t.Errorf("Request got permitted by middleware, want it to be denied")
	}
}

func TestMiddlewareAllowsPostWithTokenViaForm(t *testing.T) {
	const token = "bXVsdGlwYXNz"

	// Send the token via form
	form := url.Values{}
	form.Set(FormField, token)
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Send same token via cookie
	r.AddCookie(&http.Cookie{Name: "homeauth_csrf", Value: token})

	w := httptest.NewRecorder()
	spy := spyHandler{}
	handler := Middleware(false)(&spy)

	handler.ServeHTTP(w, r)

	response := w.Result()

	if response.StatusCode != http.StatusOK {
		t.Errorf("Got status code %d, want %d", response.StatusCode, http.StatusOK)
	}

	if !spy.Called {
		t.Errorf("Request got denied by middlware, want it to be permitted")
	}
}

func TestMiddlewareBlocksPostWithWrongTokenViaForm(t *testing.T) {
	// Send a token via form - which won't match the new token that's randomly
	// generated as we're not sending it via cookie as well
	form := url.Values{}
	form.Set(FormField, "Zml2ZSBtaW51dGVzLCBUdXJraXNo")
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	w := httptest.NewRecorder()
	spy := spyHandler{}
	handler := Middleware(false)(&spy)

	handler.ServeHTTP(w, r)

	response := w.Result()

	if response.StatusCode != http.StatusBadRequest {
		t.Errorf("Got status code %d, want %d", response.StatusCode, http.StatusBadRequest)
	}

	if spy.Called {
		t.Errorf("Request got permitted by middleware, want it to be denied")
	}
}

func TestMiddlewareAllowsPostWithTokenViaHeader(t *testing.T) {
	const token = "aSBrbm93IGt1bmcgZnU"

	r := httptest.NewRequest(http.MethodPost, "/", nil)

	// Send the token via header
	r.Header.Set(HeaderName, token)

	// Send same token via cookie
	r.AddCookie(&http.Cookie{Name: "homeauth_csrf", Value: token})

	w := httptest.NewRecorder()
	spy := spyHandler{}
	handler := Middleware(false)(&spy)

	handler.ServeHTTP(w, r)

	response := w.Result()

	if response.StatusCode != http.StatusOK {
		t.Errorf("Got status code %d, want %d", response.StatusCode, http.StatusOK)
	}

	if !spy.Called {
		t.Errorf("Request got denied by middlware, want it to be permitted")
	}
}

func TestMiddlewareBlocksPostWithWrongTokenViaHeader(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/", nil)

	// Send the token via header, which won't match as we're not also sending it
	// via cookie
	r.Header.Set(HeaderName, "aSB3aWxsIG5vdCBmZWFy")

	w := httptest.NewRecorder()
	spy := spyHandler{}
	handler := Middleware(false)(&spy)

	handler.ServeHTTP(w, r)

	response := w.Result()

	if response.StatusCode != http.StatusBadRequest {
		t.Errorf("Got status code %d, want %d", response.StatusCode, http.StatusBadRequest)
	}

	if spy.Called {
		t.Errorf("Request got permitted by middleware, want it to be denied")
	}
}

// TestGetTokenFromContext checks that we are able to retrieve the token
// from the request context using GetToken.
func TestGetTokenFromContext(t *testing.T) {
	const token = "bm90IHdpdGhvdXQgaW5jaWRlbnQ"

	reflectToken := func(w http.ResponseWriter, r *http.Request) {
		t := GetToken(r)
		fmt.Fprint(w, t)
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: "homeauth_csrf", Value: token})
	w := httptest.NewRecorder()
	handler := Middleware(false)(http.HandlerFunc(reflectToken))

	handler.ServeHTTP(w, r)

	response := w.Result()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != token {
		t.Errorf("Response body not equal to token, got body=%q, want %q", body, token)
	}
}

// TestGetTokenFromContextNewToken checks that when no cookie is sent via the
// request, and a new CSRF token is generated, it is still immediately available
// in the request context. In other words: the token is being set on the request
// context and not just being retrieved from the cookie value.
func TestGetTokenFromContextNewToken(t *testing.T) {
	reflectToken := func(w http.ResponseWriter, r *http.Request) {
		t := GetToken(r)
		fmt.Fprint(w, t)
	}
	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler := Middleware(false)(http.HandlerFunc(reflectToken))

	handler.ServeHTTP(w, r)

	response := w.Result()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	cookie := getCookie(response)
	if cookie == nil {
		t.Fatalf("No cookie named %q found in response, want one", cookieName)
	}

	if string(body) != cookie.Value {
		t.Errorf("Expected cookie and response body to match, got cookie=%q and body=%q", cookie.Value, body)
	}
}

// getCookieValue returns the CSRF cookie set in the response, or nil if no CSRF
// cookie was set.
func getCookie(response *http.Response) *http.Cookie {
	for _, cookie := range response.Cookies() {
		if cookie.Name == cookieName {
			return cookie
		}
	}
	return nil
}
