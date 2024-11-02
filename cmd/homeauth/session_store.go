package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/andrew-d/homeauth/internal/jsonfile"
	"github.com/andrew-d/homeauth/sessions"
)

// sessionStoreData is the data stored in our session store; it is a wrapper
// around sessionData that contains values that are only used by the session
// store and not by the rest of the application.
type sessionStoreData struct {
	Data   sessionData // the inner data for the application
	Expiry time.Time   // when the session expires
	Token  string      // the session token

	// TODO: this isn't a generic type because we know that we're storing a
	// sessionData in the session store, however it might be a bit cleaner
	// to do that to enforce that we don't accidentally violate
	// abstractions. Think more about this.
}

// sessionStoreDataJSON is the JSON representation of sessionStoreData, so that
// we can store the Expiry as a Unix timestamp.
//
// Additionally, we set JSON tags to reduce the size of data stored in the database,
// since sessions are expected to be reasonably numerous.
type sessionStoreJSON struct {
	Data   sessionData `json:"d"`
	Expiry int64       `json:"exp"`
	Token  string      `json:"t"`
}

// MarshalJSON implements the json.Marshaler interface.
func (ssd sessionStoreData) MarshalJSON() ([]byte, error) {
	return json.Marshal(sessionStoreJSON{
		Data:   ssd.Data,
		Expiry: ssd.Expiry.UnixMilli(),
		Token:  ssd.Token,
	})
}

// UnmarshalJSON implements the json.Unmarshaler interface.
func (ssd *sessionStoreData) UnmarshalJSON(data []byte) error {
	var ssdJSON sessionStoreJSON
	if err := json.Unmarshal(data, &ssdJSON); err != nil {
		return err
	}
	ssd.Data = ssdJSON.Data
	ssd.Expiry = time.UnixMilli(ssdJSON.Expiry)
	ssd.Token = ssdJSON.Token
	return nil
}

type dbSessionStore struct {
	db      *jsonfile.JSONFile[data]
	timeNow func() time.Time
}

var _ sessions.Store[sessionData] = (*dbSessionStore)(nil)

// newDBSessionStore returns a new dbSessionStore instance.
func newDBSessionStore(db *jsonfile.JSONFile[data]) *dbSessionStore {
	return &dbSessionStore{
		db:      db,
		timeNow: time.Now,
	}
}

func (dbs *dbSessionStore) keyFor(token string) string {
	// Note: we may want to use a *sync.Pool for this since a sha256 hash
	// is fairly large and we allocate a new one each time we hash a token.
	//
	// Not doing for now since this it's extra complexity and we likely
	// won't have that much traffic.
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// Find implements the Store interface.
func (dbs *dbSessionStore) Find(_ context.Context, token string, into *sessionData) error {
	key := dbs.keyFor(token)

	var err error
	dbs.db.Read(func(d *data) {
		data, ok := d.Sessions[key]
		if !ok {
			err = sessions.ErrNotFound
			return
		}

		// Unlikely, but confirm that the token actually matches. This should
		// never happen since we use a cryptographic hash.
		if data.Token != token {
			err = sessions.ErrNotFound
			return
		}

		now := dbs.timeNow()
		isExpired := data.Expiry.Before(now)
		if isExpired {
			err = sessions.ErrNotFound
			return
		}

		*into = data.Data
	})
	return err
}

// Delete implements the Store interface.
func (dbs *dbSessionStore) Delete(_ context.Context, token string) error {
	return dbs.db.Write(func(d *data) error {
		delete(d.Sessions, dbs.keyFor(token))
		return nil
	})
}

// Commit implements the Store interface.
func (dbs *dbSessionStore) Commit(_ context.Context, token string, d *sessionData, expiry time.Time) error {
	return dbs.db.Write(func(data *data) error {
		if data.Sessions == nil {
			data.Sessions = make(map[string]sessionStoreData)
		}
		data.Sessions[dbs.keyFor(token)] = sessionStoreData{
			Data:   *d,
			Expiry: expiry,
			Token:  token,
		}
		return nil
	})
}

// List implements the Store interface.
func (dbs *dbSessionStore) List(_ context.Context) (map[string]sessionData, error) {
	now := dbs.timeNow()

	var tokens map[string]sessionData
	dbs.db.Read(func(d *data) {
		for _, data := range d.Sessions {
			if data.Expiry.Before(now) {
				continue
			}
			if tokens == nil {
				tokens = make(map[string]sessionData)
			}
			tokens[data.Token] = data.Data
		}
	})
	return tokens, nil
}

// CleanExpired removes all expired sessions from the store. It is the
// responsibility of the user of the store to call this method periodically.
func (dbs *dbSessionStore) CleanExpired() error {
	now := dbs.timeNow()
	return dbs.db.Write(func(d *data) error {
		for key, data := range d.Sessions {
			if data.Expiry.Before(now) {
				delete(d.Sessions, key)
			}
		}
		return nil
	})
}
