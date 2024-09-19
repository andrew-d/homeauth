package db

import (
	"encoding/json"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
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

	// WebAuthnID is the user handle for WebAuthn. This is a random value
	// of 64 bytes.
	WebAuthnID []byte `json:",omitempty"`
}

// Session is a user session in the database.
type Session struct {
	ID       string
	UserUUID string
	Data     map[string]any `json:",omitempty"`

	// Expiry is the time that the session expires and is no longer valid;
	// it is used both to clean up old sessions from the database, and to
	// enforce session timeouts on the client by expiring the session cookie.
	//
	// Sessions that are ephemeral have no explicit expiry time, and the
	// Expiry field is the zero value.
	Expiry JSONTime `json:",omitempty"`

	// IsEphemeral is whether this session is ephemeral; i.e. should not be
	// persisted by the client, and should be deleted when the browser is
	// closed. These sessions are removed from the database upon boot, or
	// if they haven't seen activity in a while.
	IsEphemeral bool `json:",omitempty"`

	// LastActivity is the last time that this session was used. This is
	// updated on every request, but no more than once every minute.
	LastActivity JSONTime

	// WebAuthnSession is the WebAuthn session data for this session.
	WebAuthnSession *webauthn.SessionData `json:",omitempty"`
}

// IsAuthenticated returns whether the given Session represents an
// authenticated user.
func (s *Session) IsAuthenticated() bool {
	return s.UserUUID != ""
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

// WebAuthnCredential is a WebAuthn credential for a user.
type WebAuthnCredential struct {
	// Embed the type from the WebAuthn library.
	webauthn.Credential

	// UserUUID is the UUID of the user that this credential is for.
	UserUUID string
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
