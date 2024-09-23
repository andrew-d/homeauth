package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/andrew-d/homeauth/internal/db"
	"github.com/descope/virtualwebauthn"
	"github.com/go-webauthn/webauthn/protocol"
)

func TestWebauthnLogin(t *testing.T) {
	idp, server := newTestServer(t)
	client := getTestClient(t, server)

	// Make a fake session for this user
	const username = "test-user"
	u, _ := url.Parse(server.URL)
	sessionCookie := makeFakeSession(t, idp, username)
	client.Jar.SetCookies(u, []*http.Cookie{sessionCookie})

	// Start by registering a virtual WebAuthn client with the server.
	cred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)

	rp := virtualwebauthn.RelyingParty{
		Name:   "homeauth",
		ID:     "127.0.0.1", // NOTE: breaks if no IPv4 but that seems fine
		Origin: server.URL,
	}
	authenticator := virtualwebauthn.NewAuthenticator()

	t.Run("Register", func(t *testing.T) {
		resp, err := client.Post(server.URL+"/account/webauthn/register", "application/json", nil)
		if err != nil || resp.StatusCode != 200 {
			t.Fatalf("failed to register virtual WebAuthn client: %v", err)
		} else if resp.StatusCode != 200 {
			t.Fatalf("failed to register virtual WebAuthn client: status %d", resp.StatusCode)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("failed to read response body: %v", err)
		}

		attestationOptions, err := virtualwebauthn.ParseAttestationOptions(string(body))
		if err != nil {
			t.Fatalf("failed to parse attestation options: %v", err)
		}
		if cred.IsExcludedForAttestation(*attestationOptions) {
			t.Fatalf("credential is excluded for attestation")
		}

		// Assert that RP options match
		if rp.ID != attestationOptions.RelyingPartyID {
			t.Fatalf("unexpected RP ID: got %q, want %q", attestationOptions.RelyingPartyID, rp.ID)
		}
		if rp.Name != attestationOptions.RelyingPartyName {
			t.Fatalf("unexpected RP name: got %q, want %q", attestationOptions.RelyingPartyName, rp.Name)
		}

		// Create attestation response that we can send to the server.
		attestationResponse := virtualwebauthn.CreateAttestationResponse(rp, authenticator, cred, *attestationOptions)

		// Send the registration response to the server.
		resp, err = client.Post(server.URL+"/account/webauthn/register-complete", "application/json", strings.NewReader(attestationResponse))
		if err != nil || resp.StatusCode != 200 {
			t.Fatalf("failed to complete registration: %v", err)
		} else if resp.StatusCode != 200 {
			t.Fatalf("failed to complete registration: status %d", resp.StatusCode)
		}
		defer resp.Body.Close()
		webauthnCredential, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("failed to read response body: %v", err)
		}
		t.Logf("registered WebAuthn credential: %s", webauthnCredential)
	})

	t.Run("Login", func(t *testing.T) {
		// Use a new HTTP client to simulate a login.
		client := getTestClient(t, server)

		type webauthnStartBody struct {
			Username string `json:"username"`
		}

		// Start a login as an unauthenticated user with no session; this
		// should result in the Webauthn session data being stored in the
		// ephemeral session.
		respBytes := mustPostJSONBytes[*webauthnStartBody](
			t, client,
			server.URL+"/login/webauthn",
			&webauthnStartBody{
				Username: "andrew@du.nham.ca",
			})
		var resp protocol.CredentialAssertion
		if err := json.Unmarshal(respBytes, &resp); err != nil {
			t.Fatalf("failed to unmarshal response: %v", err)
		}

		// Basic sanity check on the response.
		if want := rp.ID; resp.Response.RelyingPartyID != want {
			t.Errorf("unexpected response.RelyingPartyID: got %q, want %q", resp.Response.RelyingPartyID, want)
		}
		if t.Failed() {
			return
		}

		// Verify that we have a session with the stored session data.
		uu, _ := url.Parse(server.URL)

		var sessionID string
		for _, cookie := range client.Jar.Cookies(uu) {
			if cookie.Name == "session" {
				sessionID = cookie.Value
				break
			}
		}
		if sessionID == "" {
			t.Fatalf("no session cookie found")
		}

		var sess *db.Session
		idp.db.Read(func(d *data) {
			sess = d.Sessions[sessionID]
		})
		if sess == nil {
			t.Fatalf("no session found in database")
		}
		if !sess.IsEphemeral {
			t.Errorf("session is not ephemeral")
		}
		if sess.WebAuthnSession == nil {
			t.Errorf("no WebAuthn session found in session")
		}

		// Now, complete the login using our virtual credential.
		authenticator.AddCredential(cred)

		assertionOptions, err := virtualwebauthn.ParseAssertionOptions(string(respBytes))
		if err != nil {
			t.Fatalf("failed to parse assertion options: %v", err)
		}
		foundCredential := authenticator.FindAllowedCredential(*assertionOptions)
		if foundCredential == nil {
			t.Fatalf("no allowed credential found")
		}
		assertionResponse := virtualwebauthn.CreateAssertionResponse(rp, authenticator, cred, *assertionOptions)

		body := url.Values{
			"username":          []string{"andrew@du.nham.ca"},
			"via":               []string{"webauthn"},
			"webauthn_response": []string{assertionResponse},
		}

		loginReq, err := http.NewRequest("POST", server.URL+"/login", strings.NewReader(body.Encode()))
		if err != nil {
			t.Fatalf("failed to create login request: %v", err)
		}
		loginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		loginResp, err := client.Do(loginReq)
		if err != nil {
			t.Fatalf("failed to complete login: %v", err)
		}
		defer loginResp.Body.Close()

		// Expect that we get a redirect to the account page.
		if loginResp.StatusCode != 303 {
			t.Fatalf("failed to complete login: status %d, want 303", loginResp.StatusCode)
		}
		if loc := loginResp.Header.Get("Location"); loc != "/account" {
			t.Fatalf("unexpected redirect location: got %q, want %q", loc, "/account")
		}

		// Verify that our client has a valid session.
		var sessionCookie *http.Cookie
		for _, cookie := range client.Jar.Cookies(uu) {
			if cookie.Name == "session" {
				sessionCookie = cookie
				break
			}
		}
		if sessionCookie == nil {
			t.Fatalf("no session cookie found")
		}

		var (
			session *db.Session
			user    *db.User
		)
		idp.db.Read(func(d *data) {
			session = d.Sessions[sessionCookie.Value]
			if session != nil {
				user = d.Users[session.UserUUID]
			}
		})
		if session == nil {
			t.Fatalf("no session found in database")
		}
		if user == nil {
			t.Fatalf("no user found in database")
		}
		if user.UUID != "test-user" {
			t.Errorf("unexpected user: got %q, want %q", user.UUID, "test-user")
		}
	})
}
