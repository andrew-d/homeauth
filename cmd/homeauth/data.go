package main

import (
	"github.com/andrew-d/homeauth/internal/db"
)

type data struct {
	// Parts of the data model
	AccessTokens  map[string]*db.AccessToken          // keyed by AccessToken.Token
	MagicLinks    map[string]*db.MagicLoginLink       // keyed by MagicLoginLink.Token
	OAuthCodes    map[string]*db.OAuthCode            // keyed by OAuthCode.Code
	PendingEmails map[string]*db.PendingEmail         // keyed by PendingEmail.ID
	Users         map[string]*db.User                 // keyed by User.UUID
	WebAuthnCreds map[string][]*db.WebAuthnCredential // keyed by User.UUID

	// SCS session data
	Sessions map[string]scsSession

	// Configuration
	Config config
}

func (d *data) userByEmail(email string) *db.User {
	// This is slow but fine for now since we don't have many users.
	for _, u := range d.Users {
		if u.Email == email {
			return u
		}
	}
	return nil
}

type config struct {
	// Which OIDC clients are allowed to use this server.
	Clients map[string]*db.Client // keyed by Client.ClientID

	// Cryptographic key(s) and secrets.
	PrimarySigningKeyID string
	SigningKeys         map[string]*db.SigningKey // keyed by SigningKey.ID

	// SecureCookieKey is the secret key to use for authenticating secure
	// cookies. If empty or invalid, this will be generated and re-saved on
	// program start.
	SecureCookieKey []byte

	// Domain to set a cookie on; if empty, the domain of the request is used.
	CookieDomain string

	// 32-byte CSRF key; will be generated and re-saved if empty or invalid.
	CSRFKey []byte

	// Email sending configuration.
	Email *EmailConfig
}

type EmailConfig struct {
	// FromAddress is the email address to use as the "From" address for
	// emails from homeauth. If left empty, most email servers will use the
	// SMTP username by default.
	FromAddress string `json:",omitempty"`

	// Subject is the subject line to use for emails from homeauth. If
	// empty, a default will be used.
	Subject string `json:",omitempty"`

	// SMTPAddr is the SMTP server to use for sending emails, in Go's
	// address format (i.e. "host:port").
	SMTPServer string

	// SMTPUsername is the username to use for SMTP authentication. This is
	// also used as the "From" address.
	SMTPUsername string

	// SMTPPassword is the password to use for SMTP authentication.
	SMTPPassword string

	// UseTLS is whether to use TLS when connecting to the SMTP server.
	// This option is mutually exclusive with UseStartTLS, and if neither
	// are explicitly set, TLS will be attempted by default. To disable
	// both TLS and StartTLS, set both to false.
	UseTLS *bool `json:",omitempty"`

	// UseStartTLS is whether to use STARTTLS when connecting to the SMTP
	// server. See the UseTLS field for more information.
	UseStartTLS *bool `json:",omitempty"`
}

func (e *EmailConfig) useTLS() bool {
	// If explicitly set, use that.
	if e.UseTLS != nil {
		return *e.UseTLS
	}

	// If UseStartTLS is unset, default to using TLS (but not StartTLS).
	if e.UseStartTLS == nil {
		return true
	}

	// UseStartTLS is set, so we don't default to using TLS.
	return false
}

func (e *EmailConfig) useStartTLS() bool {
	if e.UseStartTLS != nil {
		return *e.UseStartTLS
	}
	return false
}
