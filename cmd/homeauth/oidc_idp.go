package main

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/andrew-d/homeauth/internal/db"
	"github.com/andrew-d/homeauth/internal/openidtypes"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

func (s *idpServer) serveOpenIDConfiguration(w http.ResponseWriter, r *http.Request) {
	// TODO: maybe use a separate endpoint for requests coming from localhost?

	metadata := openidtypes.ProviderMetadata{
		Issuer:                 s.serverURL,
		AuthorizationEndpoint:  s.serverURL + "/authorize/public",
		JWKS_URI:               s.serverURL + "/.well-known/jwks.json",
		UserinfoEndpoint:       s.serverURL + "/userinfo",
		TokenEndpoint:          s.serverURL + "/token",
		ScopesSupported:        []string{"openid", "email"},
		ResponseTypesSupported: []string{"id_token", "code"},
		SubjectTypesSupported:  []string{"public"},
		ClaimsSupported: []string{
			// Claims from the jwt.Claims struct
			"sub",

			// Additional claims supported by this IdP
			"email", // email address
		},
		IDTokenSigningAlgValuesSupported: []string{
			// Per the OpenID spec:
			//	"The algorithm RS256 MUST be included"
			string(jose.RS256),
		},
	}

	w.Header().Set("Content-Type", "application/json")
	jenc := json.NewEncoder(w)
	jenc.SetIndent("", "  ")
	if err := jenc.Encode(metadata); err != nil {
		http.Error(w, "failed to encode metadata", http.StatusInternalServerError)
		return
	}
}

func (s *idpServer) serveAuthorize(w http.ResponseWriter, r *http.Request) {
	// This endpoint is visited by the user that is being authenticated;
	// they're redirected here by the service they're trying to
	// authenticate to (the "relying party" / RP).

	// First, validate the request, per the OIDC spec § 3.1.2.2
	// ("Authentication Request Validation").

	// "1. The Authorization Server MUST validate all the OAuth 2.0
	// parameters according to the OAuth 2.0 specification."
	//
	// The OAuth 2.0 specification is RFC6749, and § 4.1.1 states that the
	// "response_type" and "client_id" parameters are REQUIRED, the
	// "redirect_uri" parameter is OPTIONAL, the "scope" parameter is
	// OPTIONAL, and the "state" parameter is RECOMMENDED.
	responseType := r.URL.Query().Get("response_type")
	clientID := r.URL.Query().Get("client_id")
	if responseType == "" || clientID == "" {
		http.Error(w, "missing response_type or client_id", http.StatusBadRequest)
		return
	}

	// Per RFC6749 § 3.1.2:
	//
	//	The redirection endpoint URI MUST be an absolute URI as defined
	//	by [RFC3986] Section 4.3.  The endpoint URI MAY include an
	//	"application/x-www-form-urlencoded" formatted (per Appendix B)
	//	query component ([RFC3986] Section 3.4), which MUST be retained
	//	when adding additional query parameters.  The endpoint URI MUST
	//	NOT include a fragment component.
	var redirectURI *url.URL
	if uri := r.URL.Query().Get("redirect_uri"); uri != "" {
		var err error
		redirectURI, err = url.ParseRequestURI(uri)
		if err != nil {
			http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
			return
		}
		if err := validateRedirectURI(redirectURI); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}

	// TODO: should we require the 'state' parameter, to defend against
	// poorly-implemented RPs?
	state := r.URL.Query().Get("state")
	if state == "" {
		s.logger.Warn("missing state parameter in authorization request", "redirect_uri", redirectURI)
	}

	// "2. Verify that a scope parameter is present and contains the openid
	// scope value [...]"
	scopes := strings.Split(r.URL.Query().Get("scope"), " ")
	if !slices.Contains(scopes, "openid") {
		http.Error(w, "missing openid scope", http.StatusBadRequest)
		return
	}

	// "3. The Authorization Server MUST verify that all the REQUIRED
	// parameters are present and their usage conforms to this
	// specification."
	// TODO

	// "4. If the sub (subject) Claim is requested with a specific value
	// for the ID Token, the Authorization Server MUST only send a positive
	// response if the End-User identified by that sub value has an active
	// session with the Authorization Server or has been Authenticated as a
	// result of the request. The Authorization Server MUST NOT reply with
	// an ID Token or Access Token for a different user, even if they have
	// an active session with the Authorization Server. Such a request can
	// be made either using an id_token_hint parameter or by requesting a
	// specific Claim Value as described in Section 5.5.1, if the claims
	// parameter is supported by the implementation."
	//
	// In other words: if the RP requests that we only authorize a specific
	// user, we should verify that the currently-authenticated user
	// matches.
	//
	// We don't set "claims_parameter_supported", so we only need to check
	// for the "id_token_hint" parameter.
	idTokenHint := r.URL.Query().Get("id_token_hint")
	if idTokenHint != "" {
		// "5. When an id_token_hint is present, the OP MUST validate
		// that it was the issuer of the ID Token. The OP SHOULD accept
		// ID Tokens when the RP identified by the ID Token has a
		// current session or had a recent session at the OP, even when
		// the exp time has passed."

		// TODO: implement me
		http.Error(w, "id_token_hint not implemented", http.StatusNotImplemented)
		return
	}

	// Okay, we successfully validated the request parameters. Now, see if
	// we have a user logged in.
	session, ok := s.sessions.getSession(r)

	var (
		user   *db.User
		client *db.Client
	)
	s.db.Read(func(data *data) {
		client = data.Config.Clients[clientID]
		if ok {
			user, ok = data.Users[session.UserUUID]
			if !ok {
				s.logger.Warn("session refers to non-existent user", "session", session, "user_uuid", session.UserUUID)
			}
		}
	})
	if client == nil {
		s.logger.Warn("client not found", "client_id", clientID)
		http.Error(w, "client not found", http.StatusBadRequest)
		return
	}

	if !slices.Contains(client.RedirectURIs, redirectURI.String()) {
		s.logger.Warn("client not allowed to redirect to URI",
			"client_id", clientID,
			"redirect_uri", redirectURI,
			"allowed_uris", client.RedirectURIs,
		)
		http.Error(w, "client not allowed to redirect to URI", http.StatusBadRequest)
		return
	}

	// Per the OIDC spec § 3.1.2.3:
	//
	//	The Authorization Server MUST NOT interact with the End-User in the following case:
	//
	//	The Authentication Request contains the prompt parameter with
	//	the value none. In this case, the Authorization Server MUST
	//	return an error if an End-User is not already Authenticated or
	//	could not be silently Authenticated.
	prompt := r.URL.Query().Get("prompt")
	if user == nil && prompt == "none" {
		redirectWithError(w, r, redirectURI, "login_required", "user not authenticated", state)
		return
	}
	if prompt == "login" {
		http.Error(w, "prompt=login not implemented", http.StatusNotImplemented)
		return
	}

	// Okay, if we don't have a session, redirect the user to login and
	// return them to this flow after they've done that.
	if user == nil {
		s.logger.Debug("no session; redirecting to login")
		s.redirectToLogin(w, r)
		return
	}

	// Okay, now that we've successfully authenticated a user, we need to
	// figure out what to reply to the RP with. Switch based on the
	// "response_type" parameter.
	//
	// This switch case updates the redirectURI URL to indicate what to
	// redirect to.
	switch responseType {
	case "code":
		code := &db.OAuthCode{
			Code:        randHex(16),
			Expiry:      db.JSONTime{time.Now().Add(time.Minute)},
			ClientID:    clientID,
			UserUUID:    user.UUID,
			RedirectURI: redirectURI.String(),
		}
		s.logger.Info("generated code", "code", code.Code, "user", user.Email)
		if err := s.db.Write(func(data *data) error {
			if data.OAuthCodes == nil {
				data.OAuthCodes = make(map[string]*db.OAuthCode)
			}
			data.OAuthCodes[code.Code] = code
			return nil
		}); err != nil {
			s.logger.Error("failed to save code", errAttr(err))
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		// Redirect the user back to the RP with the code.
		vals := redirectURI.Query()
		vals.Set("code", code.Code)
		if state != "" {
			vals.Set("state", state)
		}
		redirectURI.RawQuery = vals.Encode()

	default:
		http.Error(w, "unsupported response_type", http.StatusNotImplemented)
		return
	}

	http.Redirect(w, r, redirectURI.String(), http.StatusSeeOther)
}

func (s *idpServer) serveToken(w http.ResponseWriter, r *http.Request) {
	// Double-check that this is a POST request
	if r.Method != http.MethodPost {
		http.Error(w, "invalid method", http.StatusMethodNotAllowed)
		return
	}

	if gt := r.FormValue("grant_type"); gt != "authorization_code" {
		s.logger.Error("unsupported grant type", "grant_type", gt)
		http.Error(w, "unsupported grant type", http.StatusBadRequest)
		return
	}

	codeID := r.FormValue("code")
	if codeID == "" {
		http.Error(w, "missing code", http.StatusBadRequest)
		return
	}

	var (
		code   *db.OAuthCode
		user   *db.User
		client *db.Client
	)
	s.db.Read(func(data *data) {
		code = data.OAuthCodes[codeID]
		if code != nil {
			user = data.Users[code.UserUUID]
			client = data.Config.Clients[code.ClientID]
		}
	})
	if code == nil || user == nil {
		s.logger.Warn("invalid code",
			"code", codeID,
			"code_found", code != nil,
			"user_found", user != nil,
		)
		http.Error(w, "invalid code", http.StatusBadRequest)
		return
	}

	// Ensure that the code hasn't expired
	now := time.Now()
	if now.After(code.Expiry.Time) {
		s.logger.Debug("code expired", "code", code.Code, "expiry", code.Expiry, "now", time.Now())
		http.Error(w, "code expired", http.StatusBadRequest)
		return
	}

	// Per the OIDC spec § 3.1.3.2, "Token Request Validation":
	//
	// "Ensure the Authorization Code was issued to the authenticated Client."
	clientID := r.FormValue("client_id")
	if clientID != code.ClientID {
		s.logger.Warn("client ID mismatch", "client_id", clientID, "expected", code.ClientID)
		http.Error(w, "client ID mismatch", http.StatusBadRequest)
		return
	}

	// Verify that the client secret is correct.
	clientSecret := r.FormValue("client_secret")
	if !secureCompareStrings(clientSecret, client.ClientSecret) {
		s.logger.Warn("client secret mismatch",
			"client_id", clientID,
			"client_secret", clientSecret,
			"expected", client.ClientSecret,
		)
		http.Error(w, "client secret mismatch", http.StatusBadRequest)
		return
	}

	// "Verify that the Authorization Code is valid"; we did this above
	// when we fetched the token from the database.

	// "if possible, verify that the Authorization Code has not been
	// previously used"
	//
	// We do this by deleting the code from the database after it's used,
	// but giving ourselves a short grace period in case there's a network
	// issue or the user refreshes at an inopportune time.
	//
	// We do this when creating an access token, below.

	// "Ensure that the redirect_uri parameter value is identical to the
	// redirect_uri parameter value that was included in the initial
	// Authorization Request."
	providedRedirectURI := r.FormValue("redirect_uri")
	if providedRedirectURI == "" {
		// "If the redirect_uri parameter value is not present when
		// there is only one registered redirect_uri value, the
		// Authorization Server MAY return an error (since the Client
		// should have included the parameter) or MAY proceed without
		// an error (since OAuth 2.0 permits the parameter to be
		// omitted in this case)."
		//
		// TODO: check the client's redirect URIs
		http.Error(w, "missing redirect_uri", http.StatusNotImplemented)
	} else if code.RedirectURI != providedRedirectURI {
		s.logger.Warn("redirect URI mismatch",
			"provided_redirect_uri", providedRedirectURI,
			"redirect_uri", code.RedirectURI,
		)
		http.Error(w, "redirect URI mismatch", http.StatusBadRequest)
		return
	}

	// TODO: "Verify that the Authorization Code used was issued in
	// response to an OpenID Connect Authentication Request (so that an ID
	// Token will be returned from the Token Endpoint)."

	// Construct the claims that we're signing for this response, per the
	claims := openidtypes.Claims{
		Claims: jwt.Claims{
			// jti: TODO: is this required?
			ID: randHex(32),

			// "iss: REQUIRED. Issuer Identifier for the Issuer of the
			// response. The iss value is a case-sensitive URL using the
			// https scheme that contains scheme, host, and optionally,
			// port number and path components and no query or fragment
			// components."
			Issuer: s.serverURL,

			// "sub: REQUIRED. Subject Identifier. A locally unique and
			// never reassigned identifier within the Issuer for the
			// End-User, which is intended to be consumed by the Client,
			// e.g., 24400320 or AItOawmwtWwcT0k51BayewNvutrJUqsvl6qs7A4.
			//
			// It MUST NOT exceed 255 ASCII [RFC20] characters in length.
			// The sub value is a case-sensitive string."
			Subject: user.UUID,

			// "aud: REQUIRED. Audience(s) that this ID Token is intended
			// for. It MUST contain the OAuth 2.0 client_id of the Relying
			// Party as an audience value. It MAY also contain identifiers
			// for other audiences. In the general case, the aud value is
			// an array of case-sensitive strings. In the common special
			// case when there is one audience, the aud value MAY be a
			// single case-sensitive string."
			Audience: jwt.Audience{clientID},

			// "exp: REQUIRED. Expiration time on or after which the ID
			// Token MUST NOT be accepted by the RP when performing
			// authentication with the OP.
			//
			// NOTE: The ID Token expiration time is unrelated the lifetime
			// of the authenticated session between the RP and the OP."
			Expiry: jwt.NewNumericDate(now.Add(5 * time.Minute)),

			// "iat: REQUIRED. Time at which the JWT was issued. Its value
			// is a JSON number representing the number of seconds from
			// 1970-01-01T00:00:00Z as measured in UTC until the
			// date/time."
			IssuedAt: jwt.NewNumericDate(now),

			// "nbf: TODO"
			NotBefore: jwt.NewNumericDate(now.Add(-10 * time.Second)), // grace period for clock skew
		},

		// "nonce: String value used to associate a Client session with an ID
		// Token, and to mitigate replay attacks. The value is passed
		// through unmodified from the Authentication Request to the ID
		// Token. [...] If present in the Authentication Request,
		// Authorization Servers MUST include a nonce Claim in the ID
		// Token with the Claim Value being the nonce value sent in the
		// Authentication Request. Authorization Servers SHOULD perform
		// no other processing on nonce values used. The nonce value is
		// a case-sensitive string."
		Nonce: r.FormValue("nonce"),

		// "email: End-User's preferred e-mail address. Its value MUST
		// conform to the RFC 5322 [RFC5322] addr-spec syntax. The RP
		// MUST NOT rely upon this value being unique, as discussed in
		// Section 5.7"
		Email: user.Email,

		// "email_verified: True if the End-User's e-mail address has
		// been verified; otherwise false. When this Claim Value is
		// true, this means that the OP took affirmative steps to
		// ensure that this e-mail address was controlled by the
		// End-User at the time the verification was performed."
		EmailVerified: user.EmailVerified,

		// TODO: check auth_time?
	}

	signer, err := s.getJOSESigner()
	if err != nil {
		s.logger.Error("failed to get JOSE signer", errAttr(err))
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	// Sign the claims with our private key.
	idToken, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		s.logger.Error("failed to sign token", errAttr(err))
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Now, generate an access token, which is entirely different from the
	// ID token and can just be a random string that we store for later
	// use. Store it in our database for later use.
	at := &db.AccessToken{
		Token:    randHex(32),
		Expiry:   db.JSONTime{now.Add(5 * time.Minute)},
		UserUUID: user.UUID,
	}
	s.db.Write(func(data *data) error {
		if data.AccessTokens == nil {
			data.AccessTokens = make(map[string]*db.AccessToken)
		}
		data.AccessTokens[at.Token] = at

		// Remove the now-used code from the database.
		//
		// NOTE: only do this after we've done all the work required
		// and won't error out.
		delete(data.OAuthCodes, codeID)
		return nil
	})

	// Construct the actual response, per the OIDC spec § 3.1.3.3.
	resp := openidtypes.TokenResponse{
		// "The OAuth 2.0 token_type response parameter value MUST be
		// Bearer [...]"
		TokenType: "Bearer",

		// "In addition to the response parameters specified by OAuth
		// 2.0, the following parameters MUST be included in the
		// response:
		//
		//    id_token   ID Token value associated with the
		//               authenticated session."
		IDToken: idToken,

		// The actual token values.
		AccessToken: at.Token,
		ExpiresIn:   5 * 60, // 5 minutes
		// TODO: refresh token?
	}

	w.Header().Set("Content-Type", "application/json")

	// From the OIDC spec § 3.1.3.3:
	//
	//	All Token Responses that contain tokens, secrets, or other
	//	sensitive information MUST include the following HTTP response
	//	header fields and values:
	w.Header().Set("Cache-Control", "no-store")

	if err := json.NewEncoder(w).Encode(resp); err != nil {
		s.logger.Error("failed to encode token response", errAttr(err))
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

// serveUserinfo serves the OpenID Connect "userinfo" endpoint.
//
// From the OIDC spec § 5.3:
//
//	The UserInfo Endpoint is an OAuth 2.0 Protected Resource that returns
//	Claims about the authenticated End-User. To obtain the requested Claims
//	about the End-User, the Client makes a request to the UserInfo Endpoint
//	using an Access Token obtained through OpenID Connect Authentication.
//	These Claims are normally represented by a JSON object that contains a
//	collection of name and value pairs for the Claims.
func (s *idpServer) serveUserinfo(w http.ResponseWriter, r *http.Request) {
	tokenString, err := getBearerToken(r)
	if err != nil {
		s.logger.Warn("failed to get bearer token", "error", err)
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// Load the access token from the database, along with any user that it references.
	var (
		accessToken *db.AccessToken
		user        *db.User
	)
	s.db.Read(func(data *data) {
		accessToken = data.AccessTokens[tokenString]
		if accessToken != nil {
			user = data.Users[accessToken.UserUUID]
		}
	})

	now := time.Now()
	if accessToken == nil || accessToken.Expiry.Time.Before(now) {
		if accessToken == nil {
			s.logger.Warn("access token not found", "token", tokenString)
		} else {
			s.logger.Warn("access token expired",
				"token", tokenString,
				"expiry", accessToken.Expiry,
				"now", now,
			)
		}

		// Always return the same error if the token is invalid or
		// expired, so as not to leak information.
		http.Error(w, "access token not found", http.StatusUnauthorized)
		return
	}
	// The user should always be found if the access token is valid, but
	// check anyway and return the same error as above if not.
	if user == nil {
		s.logger.Warn("user not found",
			"token", tokenString,
			"user_uuid", accessToken.UserUUID,
		)
		http.Error(w, "access token not found", http.StatusUnauthorized)
		return
	}

	// Add the user UUID to the request log attributes.
	AddRequestLogAttrs(r, slog.String("user_uuid", user.UUID))

	// Construct the userinfo response
	userinfo := openidtypes.UserInfoResponse{
		Subject:       user.UUID,
		Email:         user.Email,
		EmailVerified: user.EmailVerified,
	}

	w.Header().Set("Content-Type", "application/json")
	jenc := json.NewEncoder(w)
	jenc.SetIndent("", "  ")
	if err := jenc.Encode(userinfo); err != nil {
		s.logger.Error("failed to encode userinfo response", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
}
