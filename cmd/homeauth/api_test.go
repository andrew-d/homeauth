package main

import (
	"net/url"
	"testing"
)

func TestAPIVerify(t *testing.T) {
	idp, server := newTestServer(t)
	client := getTestClient(t, server)

	// These are some fake forwarded headers that we might get from a load
	// balancer (e.g. Caddy, nginx with auth_request, etc).
	lbHeaders := []testClientOpt{
		withHeader("X-Forwarded-Method", "POST"),
		withHeader("X-Forwarded-Proto", "https"),
		withHeader("X-Forwarded-Host", "service.example.com"),
		withHeader("X-Forwarded-URI", "/some/path"),
	}

	t.Run("NoAccess", func(t *testing.T) {
		t.Run("Deny", func(t *testing.T) {
			// Create a mock request that mimics the request from a load balancer
			// (e.g. Caddy).
			resp := client.Get(server.URL+"/api/verify?behaviour=deny", lbHeaders...)

			// This should be a failure because the default behaviour is to deny access.
			if resp.StatusCode != 403 {
				t.Fatalf("unexpected status code: got %d, want 403", resp.StatusCode)
			}
		})

		t.Run("Redirect", func(t *testing.T) {
			// The same request, but with the behaviour set to 'redirect'.
			resp := client.Get(server.URL+"/api/verify?behaviour=redirect", lbHeaders...)
			if resp.StatusCode != 303 {
				t.Fatalf("unexpected status code: got %d, want 303", resp.StatusCode)
			}
			loc := resp.Header.Get("Location")
			u, err := url.Parse(loc)
			if err != nil {
				t.Fatalf("failed to parse Location header: %v", err)
			}
			if u.Path != "/login" {
				t.Fatalf("unexpected redirect path: got %q, want /login", u.Path)
			}
			// Expect that the redirect URL is the original, forwarded URL.
			const wantNext = "https://service.example.com/some/path"
			if got := u.Query().Get("next"); got != wantNext {
				t.Fatalf("unexpected redirect URL: got %q, want %q", u.Query().Get("next"), wantNext)
			}
		})
	})

	t.Run("AccessGranted", func(t *testing.T) {
		// We'll now grant access to the request by adding a session cookie.
		opts := append([]testClientOpt(nil), lbHeaders...)
		opts = append(opts, withCookie(makeFakeSession(t, idp, "test-user")))

		resp := client.Get(server.URL+"/api/verify", opts...)
		if resp.StatusCode != 200 {
			t.Fatalf("unexpected status code: got %d, want 200", resp.StatusCode)
		}
	})
}
