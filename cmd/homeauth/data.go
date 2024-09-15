package main

import "github.com/andrew-d/homeauth/internal/db"

type data struct {
	// Parts of the data model
	Users        map[string]*db.User           // keyed by User.UUID
	Sessions     map[string]*db.Session        // keyed by Session.ID
	OAuthCodes   map[string]*db.OAuthCode      // keyed by OAuthCode.Code
	Clients      map[string]*db.Client         // keyed by Client.ClientID
	AccessTokens map[string]*db.AccessToken    // keyed by AccessToken.Token
	MagicLinks   map[string]*db.MagicLoginLink // keyed by MagicLoginLink.Token

	// Cryptographic key(s) and secrets.

	PrimarySigningKeyID string
	SigningKeys         map[string]*db.SigningKey // keyed by SigningKey.ID

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
