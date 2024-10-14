package integration

import "testing"

// TestSmoke verifies that the server boots and responds to HTTP requests.
func TestSmoke(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}

	bin := buildHomeauth(t)
	ctx, addr := startHomeauth(t, bin, startOptions{Domain: "localhost"})

	// Log in
	tt := newTester(t, ctx, addr)
	tt.loginPassword("andrew@du.nham.ca", "password")
}
