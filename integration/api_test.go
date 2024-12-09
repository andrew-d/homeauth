package integration

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"text/template"
	"time"

	"github.com/andrew-d/homeauth/internal/testproc"
)

var configTemplate = template.Must(template.New("config").Parse(strings.TrimSpace(`
http://auth.example.com {
	bind unix/{{ .AuthSocket }}
	reverse_proxy {{ .AuthAddr }}
}

http://protected.example.com {
	bind unix/{{ .ProtectedSocket }}

	forward_auth {{ .AuthAddr }} {
		uri /api/verify?behaviour=redirect
		copy_headers Remote-User Remote-Groups Remote-Name Remote-Email
	}

	file_server browse {
		root {{ .ProtectedDir }}
	}
}
`)))

func TestCaddy(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}

	// Look in $PATH for the Caddy binary, along with /usr/local/bin if
	// we're on Linux or macOS (where it might be installed by the user).
	caddyBin, err := exec.LookPath("caddy")
	if err != nil {
		var found bool
		if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
			// Confirm that the file exists, is a regular file, and
			// is executable.
			st, err := os.Stat("/usr/local/bin/caddy")
			if err == nil && st.Mode().IsRegular() && st.Mode().Perm()&0111 != 0 {
				caddyBin = "/usr/local/bin/caddy"
				found = true
			}
		}

		if !found {
			if errors.Is(err, exec.ErrNotFound) {
				t.Skip("caddy not found in PATH")
			}

			t.Fatalf("caddy not found in PATH: %v", err)
		}
	}

	bin := buildHomeauth(t)
	ctx, addr := startHomeauth(t, bin, startOptions{
		Domain:    "example.com",
		ServerURL: "http://auth.example.com",
	})

	// Create a Caddy config file
	confFile, err := os.Create(filepath.Join(t.TempDir(), "Caddyfile"))
	if err != nil {
		t.Fatalf("failed to create Caddy config file: %v", err)
	}
	defer confFile.Close()

	pdir := filepath.Join(t.TempDir(), "protected")
	if err := os.Mkdir(pdir, 0755); err != nil {
		t.Fatalf("failed to create protected directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(pdir, "index.html"), []byte("Super secret"), 0644); err != nil {
		t.Fatalf("failed to write index.html: %v", err)
	}

	authSocket := filepath.Join(t.TempDir(), "auth.sock")
	protectedSocket := filepath.Join(t.TempDir(), "protected.sock")

	if err := configTemplate.Execute(confFile, map[string]any{
		"AuthAddr":        addr,
		"ProtectedDir":    pdir,
		"AuthSocket":      authSocket,
		"ProtectedSocket": protectedSocket,
	}); err != nil {
		t.Fatalf("failed to execute Caddy config template: %v", err)
	}

	// Start Caddy
	proc := testproc.New(t, caddyBin, []string{"run", "--config", confFile.Name()}, &testproc.Options{
		ShutdownSignal: syscall.SIGTERM,
		LogStdout:      true,
		LogStderr:      true,
	})

	// Wait for it to create the Unix sockets.
	proc.WaitForFiles(time.Second, authSocket, protectedSocket)

	// Create a second context that is canceled when either our original
	// context is, or the Caddy process exits.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		select {
		case <-ctx.Done():
		case <-proc.Context().Done():
			cancel()
		}
	}()

	tt := newTester(t, ctx, "http://auth.example.com")

	// Configure the http.Client to dial our Unix socket(s)
	tt.client.Transport = &http.Transport{
		DialContext: (unixSocketDialer{
			"auth.example.com":      authSocket,
			"protected.example.com": protectedSocket,
		}).DialContext,
	}

	// Verify that a request to our protected resource does not work before
	// we log in; we expect a redirect to our auth service.
	req := must(http.NewRequestWithContext(proc.Context(), "GET", "http://protected.example.com/index.html", nil))
	resp := must(tt.client.Do(req))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got status %d, want 200", resp.StatusCode)
	}
	if hostname := resp.Request.URL.Hostname(); hostname != "auth.example.com" {
		t.Fatalf("expected redirect to auth service, but got: %v", resp.Request.URL)
	}
	body := must(io.ReadAll(resp.Body))
	if bytes.Contains(body, []byte("Super secret")) {
		t.Fatalf("did not expect to find \"Super secret\" in response")
	}

	// Then log in to homeauth.
	tt.loginPassword("andrew@du.nham.ca", "password")

	// We should be able to make a request to our protected site now, and
	// the verification should work fine.
	req = must(http.NewRequestWithContext(proc.Context(), "GET", "http://protected.example.com/index.html", nil))
	resp = must(tt.client.Do(req))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got status %d, want 200", resp.StatusCode)
	}
	body = must(io.ReadAll(resp.Body))
	if string(body) != "Super secret" {
		t.Fatalf("got body %q, want %q", body, "Super secret")
	}
}
