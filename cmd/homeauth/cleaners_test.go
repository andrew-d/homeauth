package main

import (
	"context"
	"testing"
	"time"

	"github.com/andrew-d/homeauth/internal/db"
)

// testCleanFunc is a version of cleanFunc that takes the *idpServer as a
// parameter.
type testCleanFunc func(*idpServer, context.Context, time.Time, *data) error

func testCleaner(tb testing.TB, f testCleanFunc, setup func(*data, time.Time), after func(*data)) {
	idp, _ := newTestServer(tb)

	// Set up the initial state.
	now := time.Now()
	if err := idp.db.Write(func(d *data) error {
		setup(d, now)
		return nil
	}); err != nil {
		tb.Fatal(err)
	}

	// Run the cleaner.
	if err := idp.db.Write(func(d *data) error {
		return f(idp, context.Background(), now, d)
	}); err != nil {
		tb.Fatal(err)
	}

	// Verify the final state.
	idp.db.Read(func(d *data) {
		after(d)
	})
}

func TestSessionCleaner(t *testing.T) {
	testCleaner(t, (*idpServer).cleanSessions, func(d *data, now time.Time) {
		// Insert two sessions, one expired and one not.
		d.Sessions = map[string]*db.Session{
			"session1": &db.Session{
				ID:     "session1",
				Expiry: db.JSONTime{now.Add(-1 * time.Second)},
			},
			"session2": &db.Session{
				ID:     "session2",
				Expiry: db.JSONTime{now.Add(1 * time.Second)},
			},
		}
	}, func(d *data) {
		// Verify that the first session was cleaned up, but the second was not.
		if _, ok := d.Sessions["session1"]; ok {
			t.Error("session1 was not cleaned up")
		}
		if _, ok := d.Sessions["session2"]; !ok {
			t.Error("session2 was cleaned up")
		}
	})
}

func TestOAuthCleaner(t *testing.T) {
	testCleaner(t, (*idpServer).cleanOAuthCodes, func(d *data, now time.Time) {
		// Insert two codes, one expired and one not.
		d.OAuthCodes = map[string]*db.OAuthCode{
			"code1": &db.OAuthCode{
				Code:   "code1",
				Expiry: db.JSONTime{now.Add(-1 * time.Second)},
			},
			"code2": &db.OAuthCode{
				Code:   "code2",
				Expiry: db.JSONTime{now.Add(1 * time.Second)},
			},
		}
	}, func(d *data) {
		// Verify that the first code was cleaned up, but the second was not.
		if _, ok := d.OAuthCodes["code1"]; ok {
			t.Error("code1 was not cleaned up")
		}
		if _, ok := d.OAuthCodes["code2"]; !ok {
			t.Error("code2 was cleaned up")
		}
	})
}

func TestAccessTokenCleaner(t *testing.T) {
	testCleaner(t, (*idpServer).cleanAccessTokens, func(d *data, now time.Time) {
		// Insert two tokens, one expired and one not.
		d.AccessTokens = map[string]*db.AccessToken{
			"token1": &db.AccessToken{
				Token:  "token1",
				Expiry: db.JSONTime{now.Add(-1 * time.Second)},
			},
			"token2": &db.AccessToken{
				Token:  "token2",
				Expiry: db.JSONTime{now.Add(1 * time.Second)},
			},
		}
	}, func(d *data) {
		// Verify that the first token was cleaned up, but the second was not.
		if _, ok := d.AccessTokens["token1"]; ok {
			t.Error("token1 was not cleaned up")
		}
		if _, ok := d.AccessTokens["token2"]; !ok {
			t.Error("token2 was cleaned up")
		}
	})
}

func TestMagicLinkCleaner(t *testing.T) {
	testCleaner(t, (*idpServer).cleanMagicLinks, func(d *data, now time.Time) {
		// Insert two links, one expired and one not.
		d.MagicLinks = map[string]*db.MagicLoginLink{
			"link1": &db.MagicLoginLink{
				Token:  "link1",
				Expiry: db.JSONTime{now.Add(-1 * time.Second)},
			},
			"link2": &db.MagicLoginLink{
				Token:  "link2",
				Expiry: db.JSONTime{now.Add(1 * time.Second)},
			},
		}
	}, func(d *data) {
		// Verify that the first link was cleaned up, but the second was not.
		if _, ok := d.MagicLinks["link1"]; ok {
			t.Error("link1 was not cleaned up")
		}
		if _, ok := d.MagicLinks["link2"]; !ok {
			t.Error("link2 was cleaned up")
		}
	})
}
