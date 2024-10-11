package main

import (
	"time"

	"github.com/andrew-d/homeauth/internal/jsonfile"
)

type scsSession struct {
	Data         []byte `json:"d,omitempty"`
	ExpiryMillis int64  `json:"e,omitempty"`
}

type jsonFileStore struct {
	db      *jsonfile.JSONFile[data]
	timeNow func() time.Time
}

// All implements scs.IterableStore
func (j *jsonFileStore) All() (map[string][]byte, error) {
	now := j.timeNow()

	var ret map[string][]byte
	j.db.Read(func(d *data) {
		ret = make(map[string][]byte, len(d.Sessions))
		for k, v := range d.Sessions {
			if time.UnixMilli(v.ExpiryMillis).Before(now) {
				continue
			}

			ret[k] = v.Data
		}
	})
	return ret, nil
}

// Delete implements scs.Store
func (j *jsonFileStore) Delete(token string) (err error) {
	return j.db.Write(func(d *data) error {
		delete(d.Sessions, token)
		return nil
	})
}

// Find implements scs.Store
func (j *jsonFileStore) Find(token string) (b []byte, found bool, err error) {
	now := j.timeNow()

	j.db.Read(func(d *data) {
		s, ok := d.Sessions[token]
		if !ok {
			return
		}
		if time.UnixMilli(s.ExpiryMillis).Before(now) {
			return
		}

		b = s.Data
		found = true
	})
	return
}

// Commit implements scs.Store
func (j *jsonFileStore) Commit(token string, b []byte, expiry time.Time) (err error) {
	return j.db.Write(func(d *data) error {
		if d.Sessions == nil {
			d.Sessions = make(map[string]scsSession)
		}
		d.Sessions[token] = scsSession{
			Data:         b,
			ExpiryMillis: expiry.UnixMilli(),
		}
		return nil
	})
}

// Cleanup will remove all expired sessions from the store.
func (j *jsonFileStore) Cleanup() (err error) {
	now := j.timeNow()
	return j.db.Write(func(d *data) error {
		for k, v := range d.Sessions {
			if time.UnixMilli(v.ExpiryMillis).Before(now) {
				delete(d.Sessions, k)
			}
		}
		return nil
	})
}
