package sessions

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/neilotoole/slogt"
	"golang.org/x/net/publicsuffix"
)

type testSessionData struct {
	UID     int
	IsAdmin bool
	Counter int
}

func newTestManager(tb testing.TB) *Manager[testSessionData] {
	tb.Helper()
	store := NewMemStore[testSessionData]()
	mgr, err := New(&loggingStore[testSessionData]{tb, store})
	if err != nil {
		tb.Fatalf("could not create session manager: %v", err)
	}
	mgr.Log = slogt.New(tb)
	return mgr
}

type testServer struct {
	*httptest.Server
	t      *testing.T
	client *http.Client
}

func runTestServer[T any](t *testing.T, mgr *Manager[T], h http.Handler) *testServer {
	testSrv := httptest.NewServer(mgr.Middleware(h))
	t.Cleanup(testSrv.Close)
	client := testSrv.Client()

	jar, err := cookiejar.New(&cookiejar.Options{
		PublicSuffixList: publicsuffix.List,
	})
	if err != nil {
		t.Fatalf("could not create cookie jar: %v", err)
	}
	client.Jar = jar
	return &testServer{
		Server: testSrv,
		t:      t,
		client: client,
	}
}

func (t *testServer) assertResponse(url string, wantStatus int, wantBody string) {
	t.t.Helper()
	resp, err := t.client.Get(t.Server.URL + url)
	if err != nil {
		t.t.Fatalf("could not get %s: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != wantStatus {
		t.t.Errorf("%s: status = %d; want %d", url, resp.StatusCode, wantStatus)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.t.Fatalf("could not read body: %v", err)
	}
	if string(body) != wantBody {
		t.t.Errorf("%s: body = %q; want %q", url, body, wantBody)
	}
}

func (t *testServer) setCookie(cookie *http.Cookie) {
	uu, _ := url.Parse(t.Server.URL)
	t.client.Jar.SetCookies(uu, []*http.Cookie{cookie})
}

func TestBasicSessionHandling(t *testing.T) {
	mgr := newTestManager(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		mgr.Update(r.Context(), func(d *testSessionData) error {
			d.UID = 123
			d.IsAdmin = true
			return nil
		})
		w.Write([]byte("logged in\n"))
	})
	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		mgr.Delete(r.Context())
		w.Write([]byte("logged out\n"))
	})
	mux.HandleFunc("/profile", func(w http.ResponseWriter, r *http.Request) {
		session, ok := mgr.Get(r.Context())
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("unauthorized\n"))
			return
		}
		fmt.Fprintf(w, "UID: %d\n", session.UID)
		fmt.Fprintf(w, "IsAdmin: %v\n", session.IsAdmin)
		fmt.Fprintf(w, "Counter: %d\n", session.Counter)
	})
	mux.HandleFunc("/no-response", func(w http.ResponseWriter, r *http.Request) {
		if err := mgr.Update(r.Context(), func(d *testSessionData) error {
			d.Counter++
			return nil
		}); err != nil {
			t.Errorf("could not update session: %v", err)
		}

		// Explicitly do not write anything to the response.
	})

	testSrv := runTestServer(t, mgr, mux)

	// Test unauthorized access
	testSrv.assertResponse("/profile", http.StatusUnauthorized, "unauthorized\n")

	// Log in
	testSrv.assertResponse("/login", http.StatusOK, "logged in\n")

	// Test authorized access
	testSrv.assertResponse("/profile", http.StatusOK, "UID: 123\nIsAdmin: true\nCounter: 0\n")

	// Test session update without response
	testSrv.assertResponse("/no-response", http.StatusOK, "")
	testSrv.assertResponse("/profile", http.StatusOK, "UID: 123\nIsAdmin: true\nCounter: 1\n")

	// Verify that we have a session in our store.
	sessions, err := mgr.ps.List(context.Background())
	if err != nil {
		t.Fatalf("could not list sessions: %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("expected 1 session; got %d", len(sessions))
	}
	for token, session := range sessions {
		if session.UID != 123 {
			t.Errorf("session %q: UID = %d; want 123", token, session.UID)
		}
		break // only one session
	}

	// Log out
	testSrv.assertResponse("/logout", http.StatusOK, "logged out\n")

	// Test unauthorized access again
	testSrv.assertResponse("/profile", http.StatusUnauthorized, "unauthorized\n")

	// Test unauthorized access with an invalid session token.
	testSrv.setCookie(&http.Cookie{
		Name:     sessionCookieName,
		Value:    "invalid",
		Path:     "/",
		HttpOnly: true,
	})
	testSrv.assertResponse("/profile", http.StatusUnauthorized, "unauthorized\n")
}

func TestDeleteThenUpdate(t *testing.T) {
	mgr := newTestManager(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/create-session", func(w http.ResponseWriter, r *http.Request) {
		if err := mgr.Update(r.Context(), func(d *testSessionData) error {
			d.UID = 123
			return nil
		}); err != nil {
			t.Errorf("could not create session: %v", err)
			return
		}
		w.Write([]byte("created session\n"))
	})
	mux.HandleFunc("/delete-then-update", func(w http.ResponseWriter, r *http.Request) {
		mgr.Delete(r.Context())
		if err := mgr.Update(r.Context(), func(d *testSessionData) error {
			d.UID = 456
			return nil
		}); err != nil {
			t.Errorf("could not update session: %v", err)
			return
		}
		w.Write([]byte("deleted then updated\n"))
	})
	mux.HandleFunc("/profile", func(w http.ResponseWriter, r *http.Request) {
		session, ok := mgr.Get(r.Context())
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("unauthorized\n"))
			return
		}
		fmt.Fprintf(w, "UID: %d\n", session.UID)
	})

	testSrv := runTestServer(t, mgr, mux)
	testSrv.assertResponse("/create-session", http.StatusOK, "created session\n")
	testSrv.assertResponse("/profile", http.StatusOK, "UID: 123\n")
	testSrv.assertResponse("/delete-then-update", http.StatusOK, "deleted then updated\n")
	testSrv.assertResponse("/profile", http.StatusOK, "UID: 456\n")
}

func TestUpdateShallowCopies(t *testing.T) {
	mgr := newTestManager(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/update-success", func(w http.ResponseWriter, r *http.Request) {
		if err := mgr.Update(r.Context(), func(d *testSessionData) error {
			d.Counter++
			return nil
		}); err != nil {
			t.Errorf("unexpected error: %v", err)
			return
		}
		w.Write([]byte("updated\n"))
	})
	mux.HandleFunc("/update-failure", func(w http.ResponseWriter, r *http.Request) {
		// The first one will succeed.
		mgr.Update(r.Context(), func(d *testSessionData) error {
			d.Counter++
			return nil
		})

		// The second one will fail.
		mgr.Update(r.Context(), func(d *testSessionData) error {
			d.Counter++
			return errors.New("update failed")
		})
		w.Write([]byte("not updated\n"))
	})
	mux.HandleFunc("/get", func(w http.ResponseWriter, r *http.Request) {
		session, _ := mgr.Get(r.Context())
		fmt.Fprintf(w, "Counter: %d\n", session.Counter)
	})

	testSrv := runTestServer(t, mgr, mux)
	testSrv.assertResponse("/update-success", http.StatusOK, "updated\n")
	testSrv.assertResponse("/get", http.StatusOK, "Counter: 1\n")
	testSrv.assertResponse("/update-failure", http.StatusOK, "not updated\n")
	testSrv.assertResponse("/get", http.StatusOK, "Counter: 2\n") // first update succeeded, second failed
}

func TestSessionBadContext(t *testing.T) {
	mgr := newTestManager(t)

	ctx := context.Background()
	if _, ok := mgr.Get(ctx); ok {
		t.Error("Get with empty context returned a session")
	}
	mgr.Delete(ctx) // no error, but no panic

	err := mgr.Update(ctx, func(d *testSessionData) error {
		return nil
	})
	if err == nil {
		t.Error("Update with empty context did not return an error")
	}
}

func TestUpdatePropagatesError(t *testing.T) {
	mgr := newTestManager(t)

	testErr := errors.New("test error")

	// Make a fake context with bare session data.
	ctx := context.WithValue(context.Background(), contextKey, &sessionData[testSessionData]{
		state: stateNew,
	})

	err := mgr.Update(ctx, func(d *testSessionData) error {
		return testErr
	})
	if !errors.Is(err, testErr) {
		t.Errorf("Update did not propagate error: %v", err)
	}
}

func TestUpdateNested_Bad(t *testing.T) {
	// NOTE: this is an example of what *not* to do; we mutate a nested
	// pointer here which causes the second Update to fail to roll back.

	type nestedPtr struct {
		Inner *int
	}
	store := NewMemStore[nestedPtr]()
	mgr, err := New(&loggingStore[nestedPtr]{t, store})
	if err != nil {
		t.Fatalf("could not create session manager: %v", err)
	}
	mgr.Log = slogt.New(t)

	// Make a fake context with bare session data.
	ctx := context.WithValue(context.Background(), contextKey, &sessionData[nestedPtr]{
		state: stateNew,
	})

	// First update; this succeeds.
	if err := mgr.Update(ctx, func(d *nestedPtr) error {
		if d.Inner == nil {
			d.Inner = new(int)
		}
		*d.Inner = *d.Inner + 1
		return nil
	}); err != nil {
		t.Fatalf("could not update: %v", err)
	}

	// Second update; this fails, but we update the nested pointer which we
	// don't deep copy.
	if err := mgr.Update(ctx, func(d *nestedPtr) error {
		if d.Inner == nil {
			d.Inner = new(int)
		}
		*d.Inner = *d.Inner + 1 // BAD BAD BAD ❌
		return errors.New("update failed")
	}); err == nil {
		t.Fatalf("expected error, got nil")
	}

	// The second update failed, but the nested pointer was updated.
	session, _ := mgr.Get(ctx)
	if *session.Inner != 2 {
		t.Errorf("nested pointer = %d; want 2", *session.Inner)
	}

	// This is the safe way to do it.
	if err := mgr.Update(ctx, func(d *nestedPtr) error {
		var val int
		if d.Inner != nil {
			val = *d.Inner
		}
		val++
		d.Inner = &val // GOOD ✅
		return errors.New("update failed")
	}); err == nil {
		t.Fatalf("expected error, got nil")
	}

	// The third update failed, and the nested pointer was not updated.
	session, _ = mgr.Get(ctx)
	if *session.Inner != 2 {
		t.Errorf("nested pointer = %d; want 2", *session.Inner)
	}
}

func TestStoreErrors(t *testing.T) {
	testErr := errors.New("test error")
	mgr, err := New(&loggingStore[testSessionData]{
		t,
		errorStore[testSessionData]{testErr},
	})
	if err != nil {
		t.Fatalf("could not create session manager: %v", err)
	}
	mgr.Log = slogt.New(t)

	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if err := mgr.Update(r.Context(), func(d *testSessionData) error {
			d.UID = 123
			return nil
		}); err != nil {
			t.Errorf("Update should not error: %v", err)
			return
		}

		switch up := r.URL.Query().Get("method"); up {
		case "write":
			// The following write will not be seen by the client, because
			// the store will fail to persist our write, then the
			// ResponseWriter is poisoned and ignores writes after an
			// error.
			w.Write([]byte("Update error\n"))

			// The follow-up writes also don't get written.
			w.Write([]byte("more data\n"))
		case "write-header":
			// This will trigger an error in the ResponseWriter.
			w.WriteHeader(http.StatusCreated)

			// Further writes will be ignored.
			w.WriteHeader(http.StatusAccepted)
		}
	})
	mux.HandleFunc("/delete", func(w http.ResponseWriter, r *http.Request) {
		// No return error, but errors on Write/WriteHeader.
		mgr.Delete(r.Context())
	})
	mux.HandleFunc("/profile", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := mgr.Get(r.Context()); !ok {
			w.Write([]byte("no session\n"))
			return
		}
		w.Write([]byte("session\n"))
	})

	testSrv := runTestServer(t, mgr, mux)
	testSrv.assertResponse("/login?method=write", http.StatusInternalServerError, "Internal Server Error\n")
	testSrv.assertResponse("/login?method=write-header", http.StatusInternalServerError, "Internal Server Error\n")
	testSrv.assertResponse("/profile", http.StatusOK, "no session\n") // since Find returns error
	testSrv.assertResponse("/delete", http.StatusInternalServerError, "Internal Server Error\n")
}

func TestStateString(t *testing.T) {
	for _, state := range []sessionState{
		stateUnknown,
		stateNew,
		stateLoaded,
		stateModified,
		stateDeleted,
		sessionState(999), // invalid
	} {
		if state.String() == "" {
			t.Errorf("state %v: empty string", state)
		}
	}
}

type loggingStore[T any] struct {
	tb    testing.TB
	inner Store[T]
}

func (ls *loggingStore[T]) Find(ctx context.Context, token string, into *T) error {
	err := ls.inner.Find(ctx, token, into)
	ls.tb.Logf("Find(%q) = %v", token, err)
	return err
}

func (ls *loggingStore[T]) Delete(ctx context.Context, token string) error {
	err := ls.inner.Delete(ctx, token)
	ls.tb.Logf("Delete(%q) = %v", token, err)
	return err
}

func (ls *loggingStore[T]) Commit(ctx context.Context, token string, d *T, expiry time.Time) error {
	err := ls.inner.Commit(ctx, token, d, expiry)
	ls.tb.Logf("Commit(%q, %+v, %v) = %v", token, d, expiry.Format(time.RFC3339), err)
	return err
}

func (ls *loggingStore[T]) List(ctx context.Context) (map[string]T, error) {
	ret, err := ls.inner.List(ctx)
	ls.tb.Logf("List() = (%d, %v)", len(ret), err)
	return ret, err
}

type errorStore[T any] struct {
	err error
}

func (es errorStore[T]) Find(context.Context, string, *T) error              { return es.err }
func (es errorStore[T]) Delete(context.Context, string) error                { return es.err }
func (es errorStore[T]) List(context.Context) (map[string]T, error)          { return nil, es.err }
func (es errorStore[T]) Commit(context.Context, string, *T, time.Time) error { return es.err }
