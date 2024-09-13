package db

import "time"

// User is the type of a user in the database.
type User struct {
	ID           int // TODO: key by email instead?
	Email        string
	PasswordHash string
}

// Session is a user session in the database.
type Session struct {
	ID     string
	Expiry time.Time
	UserID int
	Data   map[string]any
}

// OAuthCode is a code for OAuth2 authorization code flow.
type OAuthCode struct {
	Code     string
	Expiry   time.Time
	ClientID string
	UserID   int
}
