package integration

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/andrew-d/homeauth/internal/repodir"
	"github.com/andrew-d/homeauth/internal/testproc"
	"golang.org/x/net/html"
	"golang.org/x/net/publicsuffix"
)

func buildHomeauth(tb testing.TB) string {
	tb.Helper()
	goBin, err := exec.LookPath("go")
	if err != nil {
		tb.Skip("go binary not found in PATH")
	}
	rootDir, err := repodir.Root()
	if err != nil {
		tb.Fatalf("finding root directory: %v", err)
	}

	out := filepath.Join(tb.TempDir(), "homeauth")
	cmd := exec.Command(goBin, "build", "-o", out, "./cmd/homeauth")
	cmd.Dir = rootDir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		tb.Fatalf("building homeauth: %v", err)
	}
	return out
}

const testConfigFile = `{
  "Config": {
    "CookieDomain": %q
  },
  "Users": {
    "a666702e-fc59-4175-9885-01282eaf49da": {
      "UUID": "a666702e-fc59-4175-9885-01282eaf49da",
      "Email": "andrew@du.nham.ca",
      "PasswordHash": "$argon2id$v=19$m=65536,t=1,p=4$dGVzdDEyMzQ$XdbBVl1PgOPDzbRIwKKoVw"
    }
  }
}`

type startOptions struct {
	Domain    string // Cookie domain, required
	ServerURL string // --server-url flag, optional
}

func startHomeauth(tb testing.TB, bin string, opts startOptions) (context.Context, string) {
	tb.Helper()

	if opts.Domain == "" {
		tb.Fatal("Domain option is required")
	}

	// Write out database file.
	tdir := tb.TempDir()
	dbPath := filepath.Join(tdir, "data.json")
	if err := os.WriteFile(
		dbPath,
		[]byte(fmt.Sprintf(testConfigFile, opts.Domain)),
		0o644,
	); err != nil {
		tb.Fatalf("writing config file: %v", err)
	}

	// Create listener in parent process and pass to child.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("error listening: %v", err)
	}
	tb.Cleanup(func() { ln.Close() })
	lnFile, err := ln.(*net.TCPListener).File()
	if err != nil {
		tb.Fatalf("error getting FD for listener: %v", err)
	}

	addr := ln.Addr().(*net.TCPAddr)
	tb.Logf("server listening on: %v", addr)

	args := []string{
		"--verbose",
		"--listen", "fd://3",
		"--db", dbPath,
		"--cookies-secure=false",
	}
	if opts.ServerURL != "" {
		args = append(args, "--server-url", opts.ServerURL)
	}

	proc := testproc.New(tb, bin, args, &testproc.Options{
		ExtraFiles: []*os.File{lnFile},

		ShutdownSignal: syscall.SIGTERM,
		LogStdout:      true,
		LogStderr:      true,
	})

	// Wait until the server is running.
	serverAddr := fmt.Sprintf("http://localhost:%d", addr.Port)
	livezURL := serverAddr + "/livez"
	proc.WaitForHttpOK(100*time.Millisecond, http.DefaultClient, livezURL)

	// If the Wait failed, it will log an error but continue; we want to
	// abort the test, so call FailNow to do that.
	if tb.Failed() {
		tb.FailNow()
	}
	return proc.Context(), serverAddr
}

type tester struct {
	tb     testing.TB
	ctx    context.Context
	client *http.Client
	addr   string
}

func newTester(tb testing.TB, ctx context.Context, addr string) *tester {
	jar, err := cookiejar.New(&cookiejar.Options{
		PublicSuffixList: publicsuffix.List,
	})
	if err != nil {
		tb.Fatalf("failed to create cookie jar: %v", err)
	}

	ret := &tester{
		tb:  tb,
		ctx: ctx,
		client: &http.Client{
			Jar: jar,
		},
		addr: addr,
	}
	tb.Cleanup(ret.client.CloseIdleConnections)
	return ret
}

func (t *tester) MustGet(path string) *http.Response {
	req, err := http.NewRequestWithContext(t.ctx, "GET", t.addr+path, nil)
	if err != nil {
		t.tb.Fatalf("creating GET request %q: %v", path, err)
	}
	resp, err := t.client.Do(req)
	if err != nil {
		t.tb.Fatalf("making GET request %q: %v", path, err)
	}
	return resp
}

func (t *tester) loginPassword(user, password string) {
	// Get the /login page to extract the CSRF token
	resp := t.MustGet("/login")
	if resp.StatusCode != http.StatusOK {
		t.tb.Fatalf("got status %d, want 200", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)

	csrfToken := extractCSRFToken(t.tb, body)
	if csrfToken == "" {
		t.tb.Fatalf("failed to extract CSRF token")
	}

	postVals := url.Values{
		"username":           {user},
		"password":           {password},
		"via":                {"password"},
		"gorilla.csrf.Token": {csrfToken},
	}
	resp, err := t.client.PostForm(t.addr+"/login", postVals)
	if err != nil {
		t.tb.Fatalf("making POST request to /login: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.tb.Fatalf("got status %d, want 200", resp.StatusCode)
	}

	// Ensure that the user is authenticated by fetching the /account page
	resp = t.MustGet("/account")
	if resp.StatusCode != http.StatusOK {
		t.tb.Fatalf("got status %d, want 200", resp.StatusCode)
	}
	body, _ = io.ReadAll(resp.Body)
	if !bytes.Contains(body, []byte("Account Information")) {
		t.tb.Fatalf("expected 'Account Information' in body; got:\n%s", body)
	}
}

// extractCSRFToken extracts the CSRF token from an HTML document.
func extractCSRFToken(tb testing.TB, body []byte) string {
	tb.Helper()
	doc, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		tb.Fatalf("failed to parse HTML: %v", err)
	}

	const tokenName = "gorilla.csrf.Token"

	// Define a helper function to recursively traverse the HTML nodes.
	var findToken func(*html.Node) string
	findToken = func(n *html.Node) string {
		if n.Type == html.ElementNode && n.Data == "input" {
			var name, value string
			for _, attr := range n.Attr {
				if attr.Key == "name" && attr.Val == tokenName {
					name = attr.Val
				}
				if attr.Key == "value" {
					value = attr.Val
				}
			}
			if name == tokenName {
				return value
			}
		}

		// Recursively traverse child nodes.
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			if token := findToken(c); token != "" {
				return token
			}
		}

		return ""
	}

	// Start the search from the root node.
	if tok := findToken(doc); tok != "" {
		return tok
	}

	tb.Fatalf("failed to find CSRF token in HTML")
	return ""
}

// unixSocketDialer is a dialer that can dial unix sockets, and exposes a
// DialContext method.
//
// The map is from the host to dial to the path to the socket; e.g.:
//
//	unixSocketDialer{
//		"example.com": "/tmp/example.sock",
//	}
type unixSocketDialer map[string]string

func (u unixSocketDialer) DialContext(_ context.Context, _, addr string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("splitting host/port: %w", err)
	}

	sockPath, ok := u[host]
	if !ok {
		return nil, fmt.Errorf("unknown host %q", host)
	}
	return net.Dial("unix", sockPath)
}

// findBinary looks for a binary in $PATH and any platform-specific
// directories.
//
// If the binary is not found, it skips the test. If another error occurs, it
// fails the test.
func findBinary(tb testing.TB, name string) string {
	path, lookErr := exec.LookPath(name)
	if lookErr == nil {
		return path
	}

	// Look for the binary in the platform-specific directories that may
	// not have been added to $PATH.
	var paths []string
	switch runtime.GOOS {
	case "linux", "darwin":
		paths = []string{"/usr/local/bin"}
	}
	for _, dir := range paths {
		path := filepath.Join(dir, name)
		st, err := os.Stat(path)
		if err != nil {
			continue
		}

		if st.Mode().IsRegular() && st.Mode().Perm()&0111 != 0 {
			return path
		}
	}

	if errors.Is(lookErr, exec.ErrNotFound) {
		tb.Skipf("%s not found in PATH", name)
	}
	tb.Fatalf("%s not found in PATH: %v", name, lookErr)
	return ""
}
