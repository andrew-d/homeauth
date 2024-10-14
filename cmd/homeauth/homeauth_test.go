package main

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/andrew-d/homeauth/internal/db"
	"github.com/andrew-d/homeauth/pwhash"
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

func TestPasswordLogin(t *testing.T) {
	idp, server := newTestServer(t)
	client := getTestClient(t, server)

	// Create a fake password for the main user. We don't use idp.hasher
	// because it's slow; we instead create an intentionally VERY WEAK
	// password hash just for testing.
	hasher := pwhash.New(1, 1024, 1)
	pwhash := hasher.HashString("hunter2")
	if err := idp.db.Write(func(d *data) error {
		d.Users["test-user"].PasswordHash = string(pwhash)
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	t.Run("Failure", func(t *testing.T) {
		resp := client.Get(server.URL + "/login")
		assertStatus(t, resp, http.StatusOK)
		csrfToken := extractCSRFTokenFromResponse(t, resp)

		form := url.Values{
			"username": {"andrew@du.nham.ca"},
			"password": {"bad-password"},
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
		var sess *db.Session
		idp.db.Read(func(d *data) {
			sess = d.Sessions[cookie.Value]
		})
		if sess == nil {
			t.Fatalf("no session found in database")
		}
		if sess.UserUUID != "test-user" {
			t.Errorf("expected session for user test-user, got %q", sess.UserUUID)
		}
	})
}
