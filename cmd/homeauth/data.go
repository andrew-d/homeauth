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
}
