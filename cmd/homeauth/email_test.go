package main

import (
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/andrew-d/homeauth/internal/db"
)

func TestMagicLinkLogin(t *testing.T) {
	idp, server := newTestServer(t)
	client := getTestClient(t, server)

	// Start by making a request to the login endpoint stating that we want
	// to use magic link login.
	form := url.Values{}
	form.Set("username", "andrew@du.nham.ca")
	form.Set("via", "email")
	resp, err := client.PostForm(server.URL+"/login?next=/fortesting", form)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assertStatus(t, resp, http.StatusSeeOther)
	if loc := resp.Header.Get("Location"); loc != "/login/check-email" {
		t.Fatalf("expected redirect to /login/check-email, got %q", loc)
	}

	// Now get our magic link from our pending email.
	var email *db.PendingEmail
	idp.db.Read(func(d *data) {
		// Get the first one
		for _, e := range d.PendingEmails {
			email = e
			break
		}
	})
	if email == nil {
		t.Fatal("no email found")
	}

	// Extract the magic link from the email body.
	magicLink := extractMagicLink(t, email.Text)
	t.Logf("magic link: %s", magicLink)

	// Verify that it has a 'token' parameter, and then extract that.
	u, err := url.Parse(magicLink)
	if err != nil {
		t.Fatalf("parsing magic link: %v", err)
	}
	token := u.Query().Get("token")
	if token == "" {
		t.Fatalf("no token found in magic link")
	}

	// Verify that the token is valid.
	var magic *db.MagicLoginLink
	idp.db.Read(func(d *data) {
		magic = d.MagicLinks[token]
	})
	if magic == nil {
		t.Fatalf("no magic link %q found in database", token)
	}
	if magic.UserUUID != "test-user" {
		t.Errorf("expected magic link for user test-user, got %q", magic.UserUUID)
	}

	// The database should store the next URL that we want to redirect to...
	if magic.NextURL != "/fortesting" {
		t.Errorf("expected next URL to be /fortesting, got %q", magic.NextURL)
	}

	// ... and if we visit the magic link, we should be logged in.
	resp, err = client.Get(magicLink)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

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
	var sess *db.Session
	idp.db.Read(func(d *data) {
		sess = d.Sessions[cookie.Value]
		t.Logf("sessions: %+v", d.Sessions)
	})
	if sess == nil {
		t.Fatalf("no session found in database")
	}
	if sess.UserUUID != "test-user" {
		t.Errorf("expected session for user test-user, got %q", sess.UserUUID)
	}
}

func TestMagicLinkLoginBadToken(t *testing.T) {
	// Make a request with a bad token.
	_, server := newTestServer(t)
	client := getTestClient(t, server)

	resp, err := client.Get(server.URL + "/login/magic?token=bad-token")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assertStatus(t, resp, http.StatusUnauthorized)
}

func TestMagicLinkLoginExpired(t *testing.T) {
	idp, server := newTestServer(t)
	client := getTestClient(t, server)

	// Create a magic link that's already expired.
	if err := idp.db.Write(func(d *data) error {
		d.MagicLinks = map[string]*db.MagicLoginLink{
			"expired-token": &db.MagicLoginLink{
				Token:    "expired-token",
				Expiry:   db.JSONTime{Time: time.Now().Add(-1 * time.Minute)},
				UserUUID: "test-user",
			},
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	resp, err := client.Get(server.URL + "/login/magic?token=expired-token")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	assertStatus(t, resp, http.StatusUnauthorized)

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "expired token") {
		t.Errorf("expected error message about expired token, got %q", body)
	}
}

func TestLogoutRemovesMagicLoginLinks(t *testing.T) {
	idp, server := newTestServer(t)
	client := getTestClient(t, server)

	for _, endpoint := range []string{
		"/account/logout",
		"/account/logout-other-sessions",
	} {
		t.Run(endpoint, func(t *testing.T) {
			// Create a fake session for a user and verify it works.
			const username = "test-user"
			req, err := http.NewRequest("GET", server.URL+"/account", nil)
			if err != nil {
				t.Fatal(err)
			}

			u, _ := url.Parse(server.URL)
			sessionCookie := makeFakeSession(t, idp, username)
			client.Jar.SetCookies(u, []*http.Cookie{sessionCookie})

			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			assertStatus(t, resp, http.StatusOK)

			// Now create a new magic link for the user.
			resp, err = client.PostForm(server.URL+"/login?next=/account", url.Values{
				"username": {"andrew@du.nham.ca"},
				"via":      {"email"},
			})
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			assertStatus(t, resp, http.StatusSeeOther)

			// Log out the user.
			resp, err = client.Post(server.URL+endpoint, "application/x-www-form-urlencoded", nil)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			assertStatus(t, resp, http.StatusSeeOther)

			// Verify that the magic link is gone.
			idp.db.Read(func(d *data) {
				if len(d.MagicLinks) != 0 {
					t.Errorf("expected no magic links, got %d", len(d.MagicLinks))
				}
			})
		})
	}
}

func extractMagicLink(tb testing.TB, body string) string {
	tb.Helper()

	// Kinda hacky, but use a regex to extract a URL starting with
	// http://localhost, since we know that it's always going to start with
	// that in tests.
	regexp := regexp.MustCompile(`http://(localhost|127.0.0.1):\d+/login/magic\?token=[a-zA-Z0-9]+`)
	matches := regexp.FindStringSubmatch(body)
	if matches == nil {
		tb.Logf("body: %s", body)
		tb.Fatalf("no magic link found in email body")
	}
	return matches[0]
}
