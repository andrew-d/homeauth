package db

import (
	"encoding/json"
	"time"
)

// User is the type of a user in the database.
type User struct {
	UUID         string
	Email        string
	PasswordHash string

	// EmailVerified is whether the user has verified their email address,
	// either via logging in with a method that requires receiving an
	// email, or via another method.
	EmailVerified bool `json:",omitempty"`
}

// Session is a user session in the database.
type Session struct {
	ID       string
	Expiry   JSONTime
	UserUUID string
	Data     map[string]any `json:",omitempty"`
}

// OAuthCode is a code for the OAuth2 authorization code flow.
type OAuthCode struct {
	Code     string
	Expiry   JSONTime
	ClientID string
	UserUUID string

	// Optional: the redirect URI that was provided, and must match when
	// exchanging this code for a token.
	RedirectURI string `json:",omitempty"`
}

// AccessToken is a token that can be used to authenticate requests.
type AccessToken struct {
	Token    string // the random token value
	Expiry   JSONTime
	UserUUID string
}

// SigningKey is a cryptographic key used for signing tokens.
type SigningKey struct {
	// ID is the unique identifier for this key.
	//
	// This is actually a uint64, but is stored as a string because floats
	// are not precise enough to store all uint64s.
	ID string

	// Algorithm is the JOSE algorithm for this key.
	Algorithm string

	// Key is the raw key material.
	Key []byte
}

// Client is a client that is allowed to use this IDP.
type Client struct {
	// Name is a friendly name for the OIDC client.
	Name string

	// ClientID is the OAuth 2.0 "Client Identifier" for this client.
	ClientID string

	// ClientSecret is the OAuth 2.0 "Client Secret" for this client.
	ClientSecret string

	// RedirectURIs is the list of URIs that this client is allowed to
	// redirect to; if none are set, all requests are rejected.
	RedirectURIs []string

	// TODO: ResponseTypes
	// TODO: Scopes
}

// MagicLoginLink is a random token that can be used to log in without a password.
type MagicLoginLink struct {
	Token    string
	Expiry   JSONTime
	UserUUID string
	NextURL  string `json:",omitempty"` // optional URL to redirect to after login
}

// JSONTime is a time.Time wrapper that serializes to/from JSON as a Unix
// timestamp in milliseconds.
type JSONTime struct {
	time.Time
}

func (jt JSONTime) MarshalJSON() ([]byte, error) {
	msec := jt.Time.UnixMilli()
	return json.Marshal(msec)
}

func (jt *JSONTime) UnmarshalJSON(b []byte) error {
	var msec int64
	if err := json.Unmarshal(b, &msec); err != nil {
		return err
	}
	*jt = JSONTime{time.UnixMilli(msec)}
	return nil
}
