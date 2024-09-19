package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/andrew-d/homeauth/internal/db"
	"github.com/andrew-d/homeauth/internal/jsonfile"
	"github.com/andrew-d/homeauth/internal/openidtypes"
	"github.com/andrew-d/homeauth/pwhash"
	"github.com/neilotoole/slogt"
)

type lazyHandler struct {
	inner atomic.Pointer[http.Handler]
}

func (h *lazyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	hh := h.inner.Load()
	if hh == nil {
		http.Error(w, "handler not initialized", http.StatusNotImplemented)
		return
	}

	(*hh).ServeHTTP(w, r)
}

func newTestServer(tb testing.TB) (*idpServer, *httptest.Server) {
	tdir := tb.TempDir()
	database, err := jsonfile.New[data](filepath.Join(tdir, "data.json"))
	if err != nil {
		tb.Fatalf("failed to create database: %v", err)
	}

	// Set up some fake data in our database.
	if err := database.Write(func(d *data) error {
		d.Users = map[string]*db.User{
			"test-user": &db.User{
				UUID:  "test-user",
				Email: "andrew@du.nham.ca",
			},
		}
		d.Clients = map[string]*db.Client{
			"test-client": &db.Client{
				ClientID:     "test-client",
				ClientSecret: "test-secret",
				RedirectURIs: []string{"http://localhost/callback"},
			},
			"other-client": &db.Client{
				ClientID:     "other-client",
				ClientSecret: "other-secret",
				RedirectURIs: []string{"http://localhost/callback"},
			},
		}
		return nil
	}); err != nil {
		tb.Fatalf("failed to write initial data: %v", err)
	}

	lhandler := &lazyHandler{}
	srv := httptest.NewServer(lhandler)
	tb.Cleanup(srv.Close)

	idp := &idpServer{
		logger:    slogt.New(tb),
		serverURL: srv.URL,
		db:        database,
		hasher:    pwhash.New(2, 512*1024, 2),
	}
	if err := idp.initializeConfig(); err != nil {
		tb.Fatalf("failed to initialize config: %v", err)
	}

	// Now swap in the real handler
	handler := idp.httpHandler()
	lhandler.inner.Store(&handler)
	return idp, srv
}

func makeFakeSession(tb testing.TB, idp *idpServer, userUUID string) *http.Cookie {
	tb.Helper()

	sessionID := randHex(32)
	session := &db.Session{
		ID:       sessionID,
		UserUUID: userUUID,
		Expiry:   db.JSONTime{time.Now().Add(24 * time.Hour)},
	}

	if err := idp.db.Write(func(d *data) error {
		if d.Sessions == nil {
			d.Sessions = make(map[string]*db.Session)
		}
		d.Sessions[sessionID] = session
		return nil
	}); err != nil {
		tb.Fatalf("failed to write session: %v", err)
	}

	return sessionCookieFor(sessionID, false)
}

func TestOIDCFlow(t *testing.T) {
	idp, server := newTestServer(t)
	client := getTestClient(t, server)
	_ = idp

	t.Run("openid_provider_metadata", func(t *testing.T) {
		config := mustGetJSON[openidtypes.ProviderMetadata](t, client, server.URL+"/.well-known/openid-configuration")

		if config.Issuer == "" || config.AuthorizationEndpoint == "" || config.TokenEndpoint == "" {
			t.Fatalf("missing required fields in OIDC configuration")
		}
	})

	var code string
	t.Run("authorization_endpoint", func(t *testing.T) {
		urlVals := url.Values{
			"response_type": {"code"},
			"client_id":     {"test-client"},
			"redirect_uri":  {"http://localhost/callback"},
			"scope":         {"openid"},
			"state":         {"test-state"},
		}
		req, err := http.NewRequest("GET", server.URL+"/authorize/public?"+urlVals.Encode(), nil)
		if err != nil {
			t.Fatalf("failed to create request: %v", err)
		}
		req.AddCookie(makeFakeSession(t, idp, "test-user"))

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("failed to initiate authorization: %v", err)
		}
		defer resp.Body.Close()

		// We want to see a redirect to the client's redirect URI with a valid code.
		if resp.StatusCode < 300 || resp.StatusCode > 399 {
			t.Fatalf("expected redirect, got status code %d", resp.StatusCode)
		}

		// Check the Location header for the code
		location := resp.Header.Get("Location")
		t.Logf("Location: %s", location)

		uu, err := url.Parse(location)
		if err != nil {
			t.Fatalf("failed to parse location header: %v", err)
		}

		// Expect the redirect to the client's redirect URI
		if uu.Scheme != "http" || uu.Host != "localhost" || uu.Path != "/callback" {
			t.Fatalf("unexpected redirect location: %v, want http://localhost/callback", location)
		}

		// Ensure that we have a valid code
		code = uu.Query().Get("code")
		if code == "" {
			t.Fatalf("missing code in redirect location: %v", location)
		}
	})

	// Exchange the code for an ID token and access token
	var idToken, accessToken string
	t.Run("token_endpoint", func(t *testing.T) {
		postData := url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {code},
			"redirect_uri":  {"http://localhost/callback"},
			"client_id":     {"test-client"},
			"client_secret": {"test-secret"},
		}
		req, err := http.NewRequest("POST", server.URL+"/token", strings.NewReader(postData.Encode()))
		if err != nil {
			t.Fatalf("failed to create request for token endpoint: %v", err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("failed to request token: %v", err)
		}
		defer resp.Body.Close()

		tokenResponse := extractResponseJSON[*openidtypes.TokenResponse](t, resp)
		if tokenResponse.IDToken == "" {
			t.Errorf("missing ID token in response")
		}
		if tokenResponse.AccessToken == "" {
			t.Errorf("missing access token in response")
		}
		idToken = tokenResponse.IDToken
		accessToken = tokenResponse.AccessToken

		if tokenResponse.TokenType != "Bearer" {
			t.Errorf("unexpected token type: %v, want Bearer", tokenResponse.TokenType)
		}

		// Ensure that we have the no-store cache control header
		if cc := resp.Header.Get("Cache-Control"); !strings.Contains(cc, "no-store") {
			t.Errorf("missing no-store in Cache-Control header: %v", cc)
		}
	})

	// Verify that the access token can be used to make a userinfo request
	t.Run("userinfo_endpoint", func(t *testing.T) {
		req, err := http.NewRequest("GET", server.URL+"/userinfo", nil)
		if err != nil {
			t.Fatalf("failed to create request for userinfo endpoint: %v", err)
		}
		req.Header.Set("Authorization", "Bearer "+accessToken)

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("failed to request userinfo: %v", err)
		}
		defer resp.Body.Close()

		userInfo := extractResponseJSON[map[string]any](t, resp)
		t.Logf("userinfo: %+v", userInfo)
		if userInfo["sub"] != "test-user" {
			t.Errorf("unexpected sub in userinfo: %v, want test-user", userInfo["sub"])
		}
		if want := "andrew@du.nham.ca"; userInfo["email"] != want {
			t.Errorf("unexpected email in userinfo: %v, want %v", userInfo["email"], want)
		}
	})

	// TODO: verify the ID token
	_ = idToken
}

func TestAuthorizeFailure(t *testing.T) {
	idp, server := newTestServer(t)
	client := getTestClient(t, server)

	// Helper function to make an authorize request with URL values
	makeAuthorizeRequest := func(t *testing.T, urlVals url.Values) *http.Response {
		req, err := http.NewRequest("GET", server.URL+"/authorize/public?"+urlVals.Encode(), nil)
		if err != nil {
			t.Fatalf("failed to create request: %v", err)
		}
		req.AddCookie(makeFakeSession(t, idp, "test-user"))

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("failed to initiate authorization: %v", err)
		}
		t.Cleanup(func() { resp.Body.Close() })
		return resp
	}

	t.Run("missing_client_id", func(t *testing.T) {
		resp := makeAuthorizeRequest(t, url.Values{
			"response_type": {"code"},
			// NOTE: missing client_id
			"redirect_uri": {"http://localhost/callback"},
			"scope":        {"openid"},
			"state":        {"test-state"},
		})
		assertStatus(t, resp, http.StatusBadRequest)
	})
	t.Run("invalid_client", func(t *testing.T) {
		resp := makeAuthorizeRequest(t, url.Values{
			"response_type": {"code"},
			"client_id":     {"invalid-client"}, // NOTE: this client doesn't exist
			"redirect_uri":  {"http://localhost/callback"},
			"scope":         {"openid"},
			"state":         {"test-state"},
		})
		assertStatus(t, resp, http.StatusBadRequest)
	})
	t.Run("invalid_redirect_uri", func(t *testing.T) {
		resp := makeAuthorizeRequest(t, url.Values{
			"response_type": {"code"},
			"client_id":     {"test-client"},
			"redirect_uri":  {"http://invalid-redirect-uri"}, // NOTE: this URI is invalid
			"scope":         {"openid"},
			"state":         {"test-state"},
		})
		assertStatus(t, resp, http.StatusBadRequest)
	})
	t.Run("missing_oidc_scope", func(t *testing.T) {
		resp := makeAuthorizeRequest(t, url.Values{
			"response_type": {"code"},
			"client_id":     {"test-client"},
			"redirect_uri":  {"http://localhost/callback"},
			"state":         {"test-state"},
			// NOTE: missing scope
		})
		assertStatus(t, resp, http.StatusBadRequest)
	})
	t.Run("invalid_response_type", func(t *testing.T) {
		resp := makeAuthorizeRequest(t, url.Values{
			"response_type": {"invalid-response-type"}, // NOTE: invalid response type
			"client_id":     {"test-client"},
			"redirect_uri":  {"http://localhost/callback"},
			"scope":         {"openid"},
			"state":         {"test-state"},
		})
		assertStatus(t, resp, http.StatusNotImplemented)
	})
}

func TestTokenFailure(t *testing.T) {
	idp, server := newTestServer(t)
	client := getTestClient(t, server)

	makeTokenRequest := func(t *testing.T, urlVals url.Values) *http.Response {
		req, err := http.NewRequest("POST", server.URL+"/token", strings.NewReader(urlVals.Encode()))
		if err != nil {
			t.Fatalf("failed to create request: %v", err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("failed to initiate authorization: %v", err)
		}
		t.Cleanup(func() { resp.Body.Close() })
		return resp
	}

	// Insert a fake code into the database for testing
	const code = "test-code"
	setCode := func(t *testing.T, code string) {
		if err := idp.db.Write(func(d *data) error {
			d.OAuthCodes = map[string]*db.OAuthCode{
				code: &db.OAuthCode{
					Code:        code,
					Expiry:      db.JSONTime{time.Now().Add(5 * time.Minute)},
					ClientID:    "test-client",
					UserUUID:    "test-user",
					RedirectURI: "http://localhost/callback",
				},
			}
			return nil
		}); err != nil {
			t.Fatalf("failed to write fake code: %v", err)
		}
	}
	setCode(t, code)

	t.Run("bad_grant_type", func(t *testing.T) {
		resp := makeTokenRequest(t, url.Values{
			"grant_type":    {"invalid-grant-type"}, // NOTE: invalid grant type
			"code":          {code},
			"redirect_uri":  {"http://localhost/callback"},
			"client_id":     {"test-client"},
			"client_secret": {"test-secret"},
		})
		assertStatus(t, resp, http.StatusBadRequest)
	})
	t.Run("missing_code", func(t *testing.T) {
		resp := makeTokenRequest(t, url.Values{
			"grant_type": {"authorization_code"},
			// NOTE: missing code
			"redirect_uri":  {"http://localhost/callback"},
			"client_id":     {"test-client"},
			"client_secret": {"test-secret"},
		})
		assertStatus(t, resp, http.StatusBadRequest)
	})
	t.Run("invalid_code", func(t *testing.T) {
		resp := makeTokenRequest(t, url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {"invalid-code"}, // NOTE: invalid code
			"redirect_uri":  {"http://localhost/callback"},
			"client_id":     {"test-client"},
			"client_secret": {"test-secret"},
		})
		assertStatus(t, resp, http.StatusBadRequest)
	})
	t.Run("code_expired", func(t *testing.T) {
		// Clean up by resetting our fake code when we're done
		t.Cleanup(func() { setCode(t, code) })

		// Expire the code
		if err := idp.db.Write(func(d *data) error {
			d.OAuthCodes[code].Expiry = db.JSONTime{time.Now().Add(-1 * time.Minute)}
			return nil
		}); err != nil {
			t.Fatalf("failed to expire code: %v", err)
		}

		// Attempt to redeem the expired code
		resp := makeTokenRequest(t, url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {code},
			"redirect_uri":  {"http://localhost/callback"},
			"client_id":     {"test-client"},
			"client_secret": {"test-secret"},
		})
		assertStatus(t, resp, http.StatusBadRequest)
	})
	t.Run("missing_client_id", func(t *testing.T) {
		resp := makeTokenRequest(t, url.Values{
			"grant_type":   {"authorization_code"},
			"code":         {code},
			"redirect_uri": {"http://localhost/callback"},
			// NOTE: missing client_id
			"client_secret": {"test-secret"},
		})
		assertStatus(t, resp, http.StatusBadRequest)
	})
	t.Run("mismatched_client_id", func(t *testing.T) {
		resp := makeTokenRequest(t, url.Values{
			"grant_type":   {"authorization_code"},
			"code":         {code},
			"redirect_uri": {"http://localhost/callback"},

			// NOTE: these are a valid client's credentials, but
			// the code was issued to a different client
			"client_id":     {"other-client"},
			"client_secret": {"other-secret"},
		})
		assertStatus(t, resp, http.StatusBadRequest)
	})
	t.Run("missing_client_secret", func(t *testing.T) {
		resp := makeTokenRequest(t, url.Values{
			"grant_type":   {"authorization_code"},
			"code":         {code},
			"redirect_uri": {"http://localhost/callback"},
			"client_id":    {"test-client"},
			// NOTE: missing client_secret
		})
		assertStatus(t, resp, http.StatusBadRequest)
	})
	t.Run("mismatched_client_secret", func(t *testing.T) {
		resp := makeTokenRequest(t, url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {code},
			"redirect_uri":  {"http://localhost/callback"},
			"client_id":     {"test-client"},
			"client_secret": {"invalid-secret"}, // NOTE: invalid secret
		})
		assertStatus(t, resp, http.StatusBadRequest)
	})
	t.Run("different_redirect_uri", func(t *testing.T) {
		resp := makeTokenRequest(t, url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {code},
			"redirect_uri":  {"http://different-redirect-uri"}, // NOTE: different URI
			"client_id":     {"test-client"},
			"client_secret": {"test-secret"},
		})
		assertStatus(t, resp, http.StatusBadRequest)
	})

	t.Run("code_cannot_be_redeemed_twice", func(t *testing.T) {
		// Clean up by resetting our fake code when we're done
		t.Cleanup(func() { setCode(t, code) })

		// Redeem the code (successfully)
		params := url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {code},
			"redirect_uri":  {"http://localhost/callback"},
			"client_id":     {"test-client"},
			"client_secret": {"test-secret"},
		}
		resp := makeTokenRequest(t, params)
		assertStatus(t, resp, http.StatusOK)

		// We should have an access token in the response
		tokenResponse := extractResponseJSON[*openidtypes.TokenResponse](t, resp)
		accessToken := tokenResponse.AccessToken
		if accessToken == "" {
			t.Fatalf("missing access token in response")
		}

		// Now, redeem the same code again
		resp = makeTokenRequest(t, params)
		assertStatus(t, resp, http.StatusBadRequest)
	})
}

func TestUserinfoFailure(t *testing.T) {
	idp, server := newTestServer(t)
	client := getTestClient(t, server)

	makeUserinfoRequest := func(t *testing.T, accessToken string) *http.Response {
		req, err := http.NewRequest("GET", server.URL+"/userinfo", nil)
		if err != nil {
			t.Fatalf("failed to create request: %v", err)
		}
		req.Header.Set("Authorization", "Bearer "+accessToken)

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("failed to initiate authorization: %v", err)
		}
		t.Cleanup(func() { resp.Body.Close() })
		return resp
	}

	t.Run("missing_access_token", func(t *testing.T) {
		resp := makeUserinfoRequest(t, "")
		assertStatus(t, resp, http.StatusUnauthorized)
	})

	t.Run("invalid_access_token", func(t *testing.T) {
		resp := makeUserinfoRequest(t, "invalid-token")
		assertStatus(t, resp, http.StatusUnauthorized)
	})

	t.Run("expired_access_token", func(t *testing.T) {
		// Insert an expired access token into the database
		tokenID := "test-token"
		if err := idp.db.Write(func(d *data) error {
			d.AccessTokens = map[string]*db.AccessToken{
				tokenID: &db.AccessToken{
					Token:    tokenID,
					UserUUID: "test-user",
					Expiry:   db.JSONTime{time.Now().Add(-1 * time.Minute)},
				},
			}
			return nil
		}); err != nil {
			t.Fatalf("failed to write fake access token: %v", err)
		}

		// Attempt to use the expired access token
		resp := makeUserinfoRequest(t, tokenID)
		assertStatus(t, resp, http.StatusUnauthorized)
	})

	t.Run("access_token_for_invalid_user", func(t *testing.T) {
		// Insert an access token for a different user
		tokenID := "test-token"
		if err := idp.db.Write(func(d *data) error {
			d.AccessTokens = map[string]*db.AccessToken{
				tokenID: &db.AccessToken{
					Token:    tokenID,
					UserUUID: "invalid-user",
					Expiry:   db.JSONTime{time.Now().Add(5 * time.Minute)},
				},
			}
			return nil
		}); err != nil {
			t.Fatalf("failed to write fake access token: %v", err)
		}

		// Attempt to use the access token
		resp := makeUserinfoRequest(t, tokenID)
		assertStatus(t, resp, http.StatusUnauthorized)
	})
}

func getTestClient(tb testing.TB, server *httptest.Server) *http.Client {
	client := server.Client()

	// We never want the client to follow redirects, as we want to see the
	// redirect URL.
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		tb.Logf("not following redirect: %v", req.URL)
		return http.ErrUseLastResponse
	}
	return client
}

func mustGetJSON[T any](tb testing.TB, client *http.Client, path string) *T {
	resp, err := client.Get(path)
	if err != nil {
		tb.Fatalf("failed to get %s: %v", path, err)
	}
	defer resp.Body.Close()

	return extractResponseJSON[*T](tb, resp)
}

func extractResponseJSON[T any](tb testing.TB, resp *http.Response) T {
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		tb.Fatalf("unexpected status code: %d", resp.StatusCode)
	}

	var val T
	if err := json.NewDecoder(resp.Body).Decode(&val); err != nil {
		tb.Fatalf("failed to decode JSON: %v", err)
	}
	return val
}

func mustPostJSON[Req, Resp any](tb testing.TB, client *http.Client, path string, body *Req) *Resp {
	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			tb.Fatalf("failed to marshal JSON: %v", err)
		}
		bodyReader = bytes.NewReader(data)
	}

	resp, err := client.Post(path, "application/json", bodyReader)
	if err != nil {
		tb.Fatalf("failed to post %s: %v", path, err)
	}
	defer resp.Body.Close()

	return extractResponseJSON[*Resp](tb, resp)
}

func assertStatus(tb testing.TB, r *http.Response, want int) {
	tb.Helper()
	if r.StatusCode != want {
		tb.Fatalf("unexpected status code: %d, want %d", r.StatusCode, want)
	}
}
