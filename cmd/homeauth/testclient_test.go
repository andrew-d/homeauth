package main

// This file contains test helpers for making requests to an httptest.Server.

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"golang.org/x/net/html"
	"golang.org/x/net/publicsuffix"
)

// testClient is a helper for making requests to an httptest.Server.
//
// TODO: bind to a particular *httptest.Server and don't require the hostname.
type testClient struct {
	tb     testing.TB
	client *http.Client
}

// getTestClient returns a testClient that can be used to make requests to the
// given httptest.Server. The testClient will not follow redirects, and has a
// valid cookie jar.
func getTestClient(tb testing.TB, server *httptest.Server) *testClient {
	tb.Helper()

	jar, err := cookiejar.New(&cookiejar.Options{
		PublicSuffixList: publicsuffix.List,
	})
	if err != nil {
		tb.Fatalf("failed to create cookie jar: %v", err)
	}

	client := server.Client()

	// We never want the client to follow redirects, as we want to see the
	// redirect URL.
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		tb.Logf("not following redirect: %v", req.URL)
		return http.ErrUseLastResponse
	}
	client.Jar = jar

	return &testClient{tb: tb, client: client}
}

// testClientOpt is an option that can be passed to a testClient's methods.
type testClientOpt func(*http.Request)

// withHeader returns a testClientOpt that sets the given header on the request.
func withHeader(k, v string) testClientOpt {
	return func(req *http.Request) {
		req.Header.Set(k, v)
	}
}

// withCSRFToken returns a testClientOpt that sets the CSRF token header on the
// request.
func withCSRFToken(tok string) testClientOpt {
	return withHeader("X-CSRF-Token", tok)
}

// withCookie returns a testClientOpt that adds the given cookie to the request.
func withCookie(c *http.Cookie) testClientOpt {
	return func(req *http.Request) {
		req.AddCookie(c)
	}
}

// SetCookies sets the given cookies in this client's cookie jar.
func (c *testClient) SetCookies(u string, cookies ...*http.Cookie) {
	uu, err := url.Parse(u)
	if err != nil {
		c.tb.Fatalf("failed to parse URL: %v", err)
	}

	c.client.Jar.SetCookies(uu, cookies)
}

// ClearAllCookies clears all cookies from this client's cookie jar.
func (c *testClient) ClearAllCookies() {
	// We can't really clear all cookies from the jar, so we just create a
	// new one.
	jar, err := cookiejar.New(&cookiejar.Options{
		PublicSuffixList: publicsuffix.List,
	})
	if err != nil {
		c.tb.Fatalf("failed to create cookie jar: %v", err)
	}
	c.client.Jar = jar
}

// MakeRequest is the underlying method for making requests to the test server.
//
// It will create a request with the provided method and path, will set the
// request body to the provided body, and will apply any options provided.
func (c *testClient) MakeRequest(
	method, path string,
	body io.Reader,
	opts ...testClientOpt,
) *http.Response {
	req, err := http.NewRequest(method, path, body)
	if err != nil {
		c.tb.Fatalf("failed to create request: %v", err)
	}
	for _, opt := range opts {
		opt(req)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		c.tb.Fatalf("failed to make request: %v", err)
	}
	c.tb.Cleanup(func() { resp.Body.Close() })
	return resp
}

// Get makes a GET request to the given path on the test server.
func (c *testClient) Get(path string, opts ...testClientOpt) *http.Response {
	return c.MakeRequest("GET", path, nil, opts...)
}

// Post makes a POST request to the given path on the test server.
func (c *testClient) Post(path, contentType string, body io.Reader, opts ...testClientOpt) *http.Response {
	opts = append([]testClientOpt{withHeader("Content-Type", contentType)}, opts...)
	return c.MakeRequest("POST", path, body, opts...)
}

// PostForm makes a POST request to the given path on the test server with the
// provided form data.
func (c *testClient) PostForm(path string, data url.Values, opts ...testClientOpt) *http.Response {
	return c.Post(path, "application/x-www-form-urlencoded", strings.NewReader(data.Encode()), opts...)
}

// GetCSRFToken fetches the CSRF token from the login page on the test server.
func (c *testClient) GetCSRFToken(base string) string {
	resp := c.Get(base + "/login")
	assertStatus(c.tb, resp, http.StatusOK)
	return extractCSRFTokenFromResponse(c.tb, resp)
}

// tcGetJSON makes a GET request to the given path on the test server and
// decodes the response JSON into the provided value.
//
// It is a freesanding function because it is generic over the response type,
// and Go does not support generic methods.
func tcGetJSON[T any](c *testClient, path string, opts ...testClientOpt) T {
	resp := c.Get(path, opts...)
	return extractResponseJSON[T](c.tb, resp)
}

// tcPostJSON makes a POST request to the given path on the test server,
// JSON-encoding the provided body, and decodes the response JSON into the
// provided value.
//
// It is a freesanding function because it is generic over the request and
// response types, and Go does not support generic methods.
func tcPostJSON[Req, Resp any](c *testClient, path string, body Req, opts ...testClientOpt) Resp {
	jsonBytes, err := json.Marshal(body)
	if err != nil {
		c.tb.Fatalf("failed to marshal JSON: %v", err)
	}

	resp := c.Post(path, "application/json", bytes.NewReader(jsonBytes), opts...)
	return extractResponseJSON[Resp](c.tb, resp)
}

// extractResponseJSON decodes the JSON from an HTTP response into the provided
// value, asserting that it has a successful status code and JSON content type.
func extractResponseJSON[T any](tb testing.TB, resp *http.Response) T {
	tb.Helper()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		tb.Fatalf("unexpected status code: %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		tb.Fatalf("unexpected content type: %v", ct)
	}

	var val T
	if err := json.NewDecoder(resp.Body).Decode(&val); err != nil {
		tb.Fatalf("failed to decode JSON: %v", err)
	}
	return val
}

// assertStatus asserts that the response has the expected status code.
func assertStatus(tb testing.TB, r *http.Response, want int) {
	tb.Helper()
	if r.StatusCode != want {
		tb.Fatalf("unexpected status code: %d, want %d", r.StatusCode, want)
	}
}

// extractCSRFTokenFromResponse extracts the CSRF token from an HTTP response.
//
// It reads the response body and then calls extractCSRFToken.
func extractCSRFTokenFromResponse(tb testing.TB, resp *http.Response) string {
	tb.Helper()
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/html") {
		tb.Fatalf("unexpected content type: %v", ct)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		tb.Fatalf("failed to read response body: %v", err)
	}
	return extractCSRFToken(tb, body)
}

// extractCSRFToken extracts the CSRF token from an HTML document.
func extractCSRFToken(tb testing.TB, body []byte) string {
	tb.Helper()
	doc, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		tb.Fatalf("failed to parse HTML: %v", err)
	}

	const tokenName = "gorilla.csrf.Token"

	// Define a helper function to recursively traverse the HTML nodes.
	var findToken func(*html.Node) string
	findToken = func(n *html.Node) string {
		if n.Type == html.ElementNode && n.Data == "input" {
			var name, value string
			for _, attr := range n.Attr {
				if attr.Key == "name" && attr.Val == tokenName {
					name = attr.Val
				}
				if attr.Key == "value" {
					value = attr.Val
				}
			}
			if name == tokenName {
				return value
			}
		}

		// Recursively traverse child nodes.
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			if token := findToken(c); token != "" {
				return token
			}
		}

		return ""
	}

	// Start the search from the root node.
	if tok := findToken(doc); tok != "" {
		return tok
	}

	tb.Fatalf("failed to find CSRF token in HTML")
	return ""
}

func assertSessionFor(tb testing.TB, idp *idpServer, token string, wantUserUUID string) {
	tb.Helper()
	if token == "" {
		tb.Fatalf("expected session token, got empty string")
	}

	var data sessionData
	if err := idp.sessionStore.Find(context.Background(), token, &data); err != nil {
		tb.Fatalf("failed to load session: %v", err)
	}
	if data.UserUUID != wantUserUUID {
		tb.Fatalf("expected session for user %q, got %q", wantUserUUID, data.UserUUID)
	}
}
