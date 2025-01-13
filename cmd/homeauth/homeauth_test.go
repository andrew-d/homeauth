package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/andrew-d/homeauth/internal/db"
	"github.com/andrew-d/homeauth/internal/must"
	"github.com/andrew-d/homeauth/pwhash"
	"golang.org/x/net/html"
)

func TestValidateRedirectURI(t *testing.T) {
	tests := []struct {
		name string
		uri  string
		want string
	}{
		{
			name: "valid",
			uri:  "http://example.com",
		},
		{
			name: "not_absolute",
			uri:  "/foo",
			want: "redirect_uri must be an absolute URI",
		},
		{
			name: "not_http",
			uri:  "ftp://example.com",
			want: "redirect_uri must be http or https",
		},
		{
			name: "no_host",
			uri:  "http:///foo",
			want: "redirect_uri must include a host",
		},
		{
			name: "has_fragment",
			uri:  "http://example.com/#foo",
			want: "redirect_uri must not include a fragment",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uu, err := url.Parse(tt.uri)
			if err != nil {
				t.Fatalf("failed to parse URI: %v", err)
			}

			got := validateRedirectURI(uu)
			if tt.want == "" && got != nil {
				t.Errorf("validateRedirectURI() = %v, want nil", got)
			} else if tt.want != "" && got == nil {
				t.Errorf("validateRedirectURI() = nil, want %v", tt.want)
			} else if tt.want != "" && got.Error() != tt.want {
				t.Errorf("validateRedirectURI() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestLivezReadyz(t *testing.T) {
	t.Parallel()

	_, server := newTestServer(t)
	client := getTestClient(t, server)

	resp := client.Get(server.URL + "/livez")
	assertStatus(t, resp, http.StatusOK)
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "ok\n" {
		t.Fatalf("got body %q, want %q", body, "ok\n")
	}

	resp = client.Get(server.URL + "/readyz")
	assertStatus(t, resp, http.StatusOK)
	body, _ = io.ReadAll(resp.Body)
	if string(body) != "ok\n" {
		t.Fatalf("got body %q, want %q", body, "ok\n")
	}
}

func TestPasswordLogin(t *testing.T) {
	idp, server := newTestServer(t)
	client := getTestClient(t, server)

	if err := idp.db.Write(func(d *data) error {
		d.Users["test-user"].PasswordHash = makeInsecureWeakPassword(t, "hunter2")
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	t.Run("Failure", func(t *testing.T) {
		// Ensure that a variety of bad passwords correctly do not work
		// for login.
		tests := []struct {
			name     string
			password string
		}{
			{"empty", ""},
			{"bad", "bad-password"},
			{"trailing_whitespace", "hunter2 "},
			{"case", "Hunter2"},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				resp := client.Get(server.URL + "/login")
				assertStatus(t, resp, http.StatusOK)
				csrfToken := extractCSRFTokenFromResponse(t, resp)

				form := url.Values{
					"username": {"andrew@du.nham.ca"},
					"password": {tt.password},
					"via":      {"password"},
				}
				resp = client.PostForm(server.URL+"/login?next=/fortesting", form, withCSRFToken(csrfToken))
				assertStatus(t, resp, http.StatusUnauthorized)

				// Expect no session cookie.
				if nn := len(resp.Cookies()); nn != 0 {
					t.Fatalf("expected no cookies, got %d", nn)
				}
			})
		}
	})

	t.Run("BadUsername", func(t *testing.T) {
		resp := client.Get(server.URL + "/login")
		assertStatus(t, resp, http.StatusOK)
		csrfToken := extractCSRFTokenFromResponse(t, resp)

		form := url.Values{
			"username": {"charlie@du.nham.ca"},
			"password": {"hunter2"},
			"via":      {"password"},
		}
		resp = client.PostForm(server.URL+"/login?next=/fortesting", form, withCSRFToken(csrfToken))
		assertStatus(t, resp, http.StatusUnauthorized)

		// Expect no session cookie.
		if nn := len(resp.Cookies()); nn != 0 {
			t.Fatalf("expected no cookies, got %d", nn)
		}
	})

	t.Run("Success", func(t *testing.T) {
		resp := client.Get(server.URL + "/login")
		assertStatus(t, resp, http.StatusOK)
		csrfToken := extractCSRFTokenFromResponse(t, resp)

		form := url.Values{
			"username": {"andrew@du.nham.ca"},
			"password": {"hunter2"},
			"via":      {"password"},
		}
		resp = client.PostForm(server.URL+"/login?next=/fortesting", form, withCSRFToken(csrfToken))
		assertStatus(t, resp, http.StatusSeeOther)
		if loc := resp.Header.Get("Location"); loc != "/fortesting" {
			t.Fatalf("expected redirect to /fortesting, got %q", loc)
		}

		// Verify that we have a session cookie...
		cookie := resp.Cookies()[0]
		if cookie.Name != "session" {
			t.Fatalf("expected session cookie, got %v", cookie)
		}

		// ... and that it's for the right user.
		assertSessionFor(t, idp, cookie.Value, "test-user")
	})

	// Verify that if a user's password is changed, their existing sessions
	// are no longer valid.
	//
	// Note that, while we don't have a password change endpoint, we still
	// want to invalidate sessions if the password is changed in the config.
	t.Run("PasswordChanged", func(t *testing.T) {
		// Remove all cookies from the jar to remove any sessions.
		client.ClearAllCookies()

		resp := client.Get(server.URL + "/login")
		assertStatus(t, resp, http.StatusOK)
		csrfToken := extractCSRFTokenFromResponse(t, resp)

		form := url.Values{
			"username": {"andrew@du.nham.ca"},
			"password": {"hunter2"},
			"via":      {"password"},
		}
		resp = client.PostForm(server.URL+"/login?next=/fortesting", form, withCSRFToken(csrfToken))
		assertStatus(t, resp, http.StatusSeeOther)
		if loc := resp.Header.Get("Location"); loc != "/fortesting" {
			t.Fatalf("expected redirect to /fortesting, got %q", loc)
		}

		// Verify that we have a session cookie...
		cookie := resp.Cookies()[0]
		if cookie.Name != "session" {
			t.Fatalf("expected session cookie, got %v", cookie)
		}

		// ... and that it's for the right user.
		assertSessionFor(t, idp, cookie.Value, "test-user")

		// Now, change the user's password.
		newPwhash := makeInsecureWeakPassword(t, "hunter3")
		if err := idp.db.Write(func(d *data) error {
			d.Users["test-user"].PasswordHash = newPwhash
			return nil
		}); err != nil {
			t.Fatal(err)
		}

		// Verify that the session cookie is no longer valid. We make a
		// request to a valid endpoint and expect a redirect to the
		// login page.
		resp = client.Get(server.URL+"/account", withCookie(cookie))
		assertStatus(t, resp, http.StatusSeeOther)
		const wantRedirect = `/login?next=%2Faccount`
		if loc := resp.Header.Get("Location"); loc != wantRedirect {
			t.Fatalf("got redirect to %q, want %q", loc, wantRedirect)
		}

		// Logging in again should result in a valid session.
		resp = client.Get(server.URL + "/login")
		assertStatus(t, resp, http.StatusOK)
		csrfToken = extractCSRFTokenFromResponse(t, resp)

		form = url.Values{
			"username": {"andrew@du.nham.ca"},
			"password": {"hunter3"},
			"via":      {"password"},
		}
		resp = client.PostForm(server.URL+"/login?next=/account", form, withCSRFToken(csrfToken))
		assertStatus(t, resp, http.StatusSeeOther)
		if loc := resp.Header.Get("Location"); loc != "/account" {
			t.Fatalf("expected redirect to /account, got %q", loc)
		}

		// And a request to the /account page should now succeed.
		resp = client.Get(server.URL + "/account")
		assertStatus(t, resp, http.StatusOK)
	})
}

func TestLoginRememberMe(t *testing.T) {
	idp, server := newTestServer(t)
	client := getTestClient(t, server)

	// Create a fake password for the main user. We don't use idp.hasher
	// because it's slow; we instead create an intentionally VERY WEAK
	// password hash just for testing.
	if err := idp.db.Write(func(d *data) error {
		d.Users["test-user"].PasswordHash = makeInsecureWeakPassword(t, "hunter2")
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// Logging in with the "remember me" checkbox checked should result in
	// a remember_username cookie.
	resp := client.Get(server.URL + "/login")
	assertStatus(t, resp, http.StatusOK)
	csrfToken := extractCSRFTokenFromResponse(t, resp)

	form := url.Values{
		"username": {"andrew@du.nham.ca"},
		"password": {"hunter2"},
		"via":      {"password"},
		"remember": {"on"},
	}
	resp = client.PostForm(server.URL+"/login?next=/fortesting", form, withCSRFToken(csrfToken))
	assertStatus(t, resp, http.StatusSeeOther)
	if loc := resp.Header.Get("Location"); loc != "/fortesting" {
		t.Fatalf("expected redirect to /fortesting, got %q", loc)
	}

	// Verify that we have a session cookie...
	var sessionCookie, rememberCookie *http.Cookie
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "session" {
			sessionCookie = cookie
		} else if cookie.Name == rememberUsernameCookieName {
			rememberCookie = cookie
		}
	}
	if sessionCookie == nil {
		t.Fatalf("expected session cookie, got %v", resp.Cookies())
	}
	if rememberCookie == nil {
		t.Fatalf("expected %q cookie, got %v", rememberUsernameCookieName, resp.Cookies())
	}

	// Fetching the login page again should result in the username being
	// pre-filled in the form.
	resp = client.Get(server.URL + "/login")
	assertStatus(t, resp, http.StatusOK)

	// Read the body so we can fetch the CSRF token and still parse it.
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read body: %v", err)
	}
	csrfToken = extractCSRFToken(t, body)

	page, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		t.Fatalf("failed to parse HTML: %v", err)
	}

	var username string
	var processNode func(*html.Node)
	processNode = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "input" {
			for _, attr := range n.Attr {
				if attr.Key == "name" && attr.Val == "username" {
					for _, attr := range n.Attr {
						if attr.Key == "value" {
							username = attr.Val
							return
						}
					}
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			processNode(c)
		}
	}
	processNode(page)

	if username != "andrew@du.nham.ca" {
		t.Fatalf("got username %q, want %q", username, "andrew@du.nham.ca")
	}

	// Logging out should remove the remember_username cookie.
	resp = client.Post(server.URL+"/account/logout", "application/x-www-form-urlencoded", nil,
		withCookie(sessionCookie), withCSRFToken(csrfToken))
	assertStatus(t, resp, http.StatusSeeOther)
	if loc := resp.Header.Get("Location"); loc != "/login" {
		t.Fatalf("expected redirect to /login, got %q", loc)
	}

	// Verify that the remember_username cookie is gone.
	resp = client.Get(server.URL + "/login")
	assertStatus(t, resp, http.StatusOK)

	for _, cookie := range resp.Cookies() {
		if cookie.Name == rememberUsernameCookieName {
			t.Fatalf("expected no %q cookie, got %v", rememberUsernameCookieName, resp.Cookies())
		}
	}

	// Verify that the page no longer has the username pre-filled.
	page, err = html.Parse(resp.Body)
	if err != nil {
		t.Fatalf("failed to parse HTML: %v", err)
	}
	processNode(page)

	if username != "" {
		t.Fatalf("got username %q, want empty", username)
	}
}

func TestLoginRememberMe_DifferentUser(t *testing.T) {
	idp, server := newTestServer(t)
	client := getTestClient(t, server)

	// Create two fake users.
	if err := idp.db.Write(func(d *data) error {
		d.Users["test-user"].PasswordHash = makeInsecureWeakPassword(t, "hunter2")

		d.Users["other-user"] = &db.User{
			UUID:         "other-user",
			Email:        "foo@example.com",
			PasswordHash: makeInsecureWeakPassword(t, "hunter3"),
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// Log in as first user, with "remember" on.
	resp := client.Get(server.URL + "/login")
	assertStatus(t, resp, http.StatusOK)
	csrfToken := extractCSRFTokenFromResponse(t, resp)

	form := url.Values{
		"username": {"andrew@du.nham.ca"},
		"password": {"hunter2"},
		"via":      {"password"},
		"remember": {"on"},
	}
	resp = client.PostForm(server.URL+"/login?next=/fortesting", form, withCSRFToken(csrfToken))
	assertStatus(t, resp, http.StatusSeeOther)
	if loc := resp.Header.Get("Location"); loc != "/fortesting" {
		t.Fatalf("expected redirect to /fortesting, got %q", loc)
	}

	// Now, log in as the second user, but with no "remember" set.
	resp = client.Get(server.URL + "/login")
	assertStatus(t, resp, http.StatusOK)
	csrfToken = extractCSRFTokenFromResponse(t, resp)

	form = url.Values{
		"username": {"foo@example.com"},
		"password": {"hunter3"},
		"via":      {"password"},
	}
	resp = client.PostForm(server.URL+"/login?next=/fortesting", form, withCSRFToken(csrfToken))
	assertStatus(t, resp, http.StatusSeeOther)
	if loc := resp.Header.Get("Location"); loc != "/fortesting" {
		t.Fatalf("expected redirect to /fortesting, got %q", loc)
	}

	// Verify that we should *not* have a remember_username cookie for the
	// login page; it should be empty because another user logged in.
	cookies := client.client.Jar.Cookies(must.Get(url.Parse(server.URL + "/login")))
	for _, cookie := range cookies {
		if cookie.Name == rememberUsernameCookieName {
			t.Fatalf("expected no %q cookie, got %v", rememberUsernameCookieName, cookies)
		}
	}
}

func makeInsecureWeakPassword(t *testing.T, password string) string {
	// We don't use idp.hasher because it's (intentionally) slow; we
	// instead create an intentionally VERY WEAK password hash using
	// parameters just for testing.
	hasher := pwhash.New(1, 1024, 1)
	pwhash := hasher.HashString(password)
	return string(pwhash)
}

func TestServeAccount(t *testing.T) {
	idp, server := newTestServer(t)
	client := getTestClient(t, server)

	// Create a few sessions for the fake user
	const numOtherSessions = 5
	for i := 0; i < numOtherSessions; i++ {
		makeFakeSession(t, idp, "test-user")
	}

	// Now fetch the /account page with a final new session; it should
	// display the number of other sessions we created above.
	resp := client.Get(server.URL+"/account", withCookie(makeFakeSession(t, idp, "test-user")))
	if resp.StatusCode != 200 {
		t.Fatalf("unexpected status code: got %d, want 200", resp.StatusCode)
	}

	// Check that the number of other sessions is displayed
	page, err := html.Parse(resp.Body)
	if err != nil {
		t.Fatalf("failed to parse HTML: %v", err)
	}

	assertTableRow(t, page, []string{"# Sessions", fmt.Sprint(numOtherSessions + 1)})
}

func assertTableRow(tb testing.TB, page *html.Node, cols []string) {
	tb.Helper()

	// extractText recursively extracts and concatenates all text nodes
	// under a given node.
	var extractText func(*html.Node) string
	extractText = func(n *html.Node) string {
		// If this is a text node, extract the text
		if n.Type == html.TextNode {
			return strings.TrimSpace(n.Data)
		}

		// Traverse the child nodes
		var text string
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			text += extractText(c)
		}
		return text
	}

	// extractColumns returns the text (per extractText) for all columns in
	// the given node. A column is either a <td> element, a <th> element,
	// or a <div> element with the class "column".
	var extractColumns func(*html.Node) []string
	extractColumns = func(n *html.Node) []string {
		// If this is a column, extract the text
		if n.Type == html.ElementNode {
			switch {
			case n.Data == "td":
				return []string{extractText(n)}
			case n.Data == "th":
				return []string{extractText(n)}
			case n.Data == "div" && nodeHasClass(n, "column"):
				return []string{extractText(n)}
			}
		}

		// Traverse the child nodes
		var cols []string
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			cols = append(cols, extractColumns(c)...)
		}
		return cols
	}

	var (
		found       bool             // did we find the right row?
		allCols     [][]string       // all columns in the table; for debugging
		processNode func(*html.Node) // recursive function processor
	)
	processNode = func(n *html.Node) {
		if n.Type == html.ElementNode {
			var rowCols []string
			switch {
			case n.Data == "tr":
				rowCols = extractColumns(n)
			case n.Data == "div" && nodeHasClass(n, "row"):
				rowCols = extractColumns(n)
			}

			if len(rowCols) > 0 {
				allCols = append(allCols, rowCols)
				if slices.Equal(rowCols, cols) {
					found = true
				}
			}
		}
		// traverse the child nodes
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			processNode(c)
		}
	}
	processNode(page)

	// Log all columns before we fail.
	for _, col := range allCols {
		tb.Logf("table row: %q", col)
	}
	if !found {
		tb.Fatalf("table row %q not found", cols)
	}
}

func nodeHasClass(n *html.Node, class string) bool {
	for _, attr := range n.Attr {
		if attr.Key != "class" {
			continue
		}

		classVals := strings.Fields(attr.Val)
		if slices.Contains(classVals, class) {
			return true
		}
	}
	return false
}
