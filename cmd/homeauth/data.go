package main

import "github.com/andrew-d/homeauth/internal/db"

type data struct {
	// IDCounter is used to allocate globally unique IDs
	IDCounter int

	Users      map[int]*db.User         // keyed by User.ID
	Sessions   map[string]*db.Session   // keyed by Session.ID
	OAuthCodes map[string]*db.OAuthCode // keyed by OAuthCode.Code
}

func (d *data) nextID() int {
	d.IDCounter++
	return d.IDCounter
}
