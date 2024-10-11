package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"testing"

	"github.com/descope/virtualwebauthn"
	"github.com/go-webauthn/webauthn/protocol"
)

func TestWebauthnLogin(t *testing.T) {
	idp, server := newTestServer(t)
	client := getTestClient(t, server)

	// Make a fake session for this user
	const username = "test-user"
	sessionCookie := makeFakeSession(t, idp, username)
	client.SetCookies(server.URL, sessionCookie)

	// Get CSRF token to use.
	csrfToken := client.GetCSRFToken(server.URL)

	// Start by registering a virtual WebAuthn client with the server.
	cred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)

	rp := virtualwebauthn.RelyingParty{
		Name:   "homeauth",
		ID:     "127.0.0.1", // NOTE: breaks if no IPv4 but that seems fine
		Origin: server.URL,
	}
	authenticator := virtualwebauthn.NewAuthenticator()

	t.Run("Register", func(t *testing.T) {
		resp := client.Post(server.URL+"/account/webauthn/register", "application/json", nil, withCSRFToken(csrfToken))
		if resp.StatusCode != 200 {
			t.Fatalf("failed to register virtual WebAuthn client: status %d", resp.StatusCode)
		}
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

		// Un-marshal then re-marshal the response to match the
		// server's expectation.
		var requestBody struct {
			WebAuthn     map[string]any `json:"webauthn"`
			FriendlyName string         `json:"friendly_name"`
		}
		if err := json.Unmarshal([]byte(attestationResponse), &requestBody.WebAuthn); err != nil {
			t.Fatalf("failed to unmarshal attestation response: %v", err)
		}
		requestBody.FriendlyName = "test-credential"

		requestBytes, err := json.Marshal(requestBody)
		if err != nil {
			t.Fatalf("failed to marshal request body: %v", err)
		}

		// Send the registration response to the server.
		resp = client.Post(
			server.URL+"/account/webauthn/register-complete",
			"application/json",
			bytes.NewReader(requestBytes),
			withCSRFToken(csrfToken),
		)
		if resp.StatusCode != 200 {
			t.Fatalf("failed to complete registration: status %d", resp.StatusCode)
		}
		webauthnCredential, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("failed to read response body: %v", err)
		}
		t.Logf("registered WebAuthn credential: %s", webauthnCredential)
	})

	t.Run("Login", func(t *testing.T) {
		// Use a new HTTP client to simulate a login.
		client := getTestClient(t, server)
		csrfToken := client.GetCSRFToken(server.URL)

		type webauthnStartBody struct {
			Username string `json:"username"`
		}

		// Start a login as an unauthenticated user with no session; this
		// should result in the Webauthn session data being stored in the
		// ephemeral session.
		respBytes := tcPostJSON[*webauthnStartBody, json.RawMessage](client,
			server.URL+"/login/webauthn",
			&webauthnStartBody{
				Username: "andrew@du.nham.ca",
			},
			withCSRFToken(csrfToken),
		)

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
		for _, cookie := range client.client.Jar.Cookies(uu) {
			if cookie.Name == webAuthnCookieName {
				sessionID = cookie.Value
				break
			}
		}
		if sessionID == "" {
			t.Fatalf("no session cookie found")
		}

		// TODO: verify that the encrypted cookie is valid?

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
		loginResp := client.PostForm(server.URL+"/login", body, withCSRFToken(csrfToken))

		// Expect that we get a redirect to the account page.
		if loginResp.StatusCode != 303 {
			t.Fatalf("failed to complete login: status %d, want 303", loginResp.StatusCode)
		}
		if loc := loginResp.Header.Get("Location"); loc != "/account" {
			t.Fatalf("unexpected redirect location: got %q, want %q", loc, "/account")
		}

		// Verify that our client has a valid session.
		var sessionCookie *http.Cookie
		for _, cookie := range client.client.Jar.Cookies(uu) {
			if cookie.Name == sessionCookieName {
				sessionCookie = cookie
				break
			}
		}
		if sessionCookie == nil {
			t.Fatalf("no session cookie found")
		}

		assertSessionFor(t, idp, sessionCookie.Value, "test-user")
	})
}
