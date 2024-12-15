package integration

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"text/template"
	"time"

	"github.com/andrew-d/homeauth/internal/must"
	"github.com/andrew-d/homeauth/internal/testproc"
)

var caddyConfigTemplate = template.Must(template.New("config").Parse(strings.TrimSpace(`
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

	caddyBin := findBinary(t, "caddy")
	bin := buildHomeauth(t)
	ctx, addr := startHomeauth(t, bin, startOptions{
		Domain:    "example.com",
		ServerURL: "http://auth.example.com",
	})

	// Create a Caddy config file
	confFile := must.Get(os.Create(filepath.Join(t.TempDir(), "Caddyfile")))
	defer confFile.Close()

	// Create protected directory we serve
	pdir := filepath.Join(t.TempDir(), "protected")
	must.Do(os.Mkdir(pdir, 0755))
	must.Do(os.WriteFile(filepath.Join(pdir, "index.html"), []byte("Super secret"), 0644))

	authSocket := filepath.Join(t.TempDir(), "auth.sock")
	protectedSocket := filepath.Join(t.TempDir(), "protected.sock")

	if err := caddyConfigTemplate.Execute(confFile, map[string]any{
		"AuthAddr":        addr,
		"ProtectedDir":    pdir,
		"AuthSocket":      authSocket,
		"ProtectedSocket": protectedSocket,
	}); err != nil {
		t.Fatalf("failed to execute Caddy config template: %v", err)
	}

	must.Do(confFile.Sync())
	must.Do(confFile.Close())

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
	req := must.Get(http.NewRequestWithContext(proc.Context(), "GET", "http://protected.example.com/index.html", nil))
	resp := must.Get(tt.client.Do(req))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got status %d, want 200", resp.StatusCode)
	}
	if hostname := resp.Request.URL.Hostname(); hostname != "auth.example.com" {
		t.Fatalf("expected redirect to auth service, but got: %v", resp.Request.URL)
	}
	body := must.Get(io.ReadAll(resp.Body))
	if bytes.Contains(body, []byte("Super secret")) {
		t.Fatalf("did not expect to find \"Super secret\" in response")
	}

	// Then log in to homeauth.
	tt.loginPassword("andrew@du.nham.ca", "password")

	// We should be able to make a request to our protected site now, and
	// the verification should work fine.
	req = must.Get(http.NewRequestWithContext(proc.Context(), "GET", "http://protected.example.com/index.html", nil))
	resp = must.Get(tt.client.Do(req))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got status %d, want 200", resp.StatusCode)
	}
	body = must.Get(io.ReadAll(resp.Body))
	if string(body) != "Super secret" {
		t.Fatalf("got body %q, want %q", body, "Super secret")
	}
}

var nginxConfigTemplate = template.Must(template.New("config").Parse(strings.TrimSpace(`
events {}

pid {{ .PIDFile }};

http {
	access_log {{ .AccessLog }};

	server {
		listen unix:{{ .AuthSocket }};
		server_name auth.example.com;

		location / {
			proxy_pass {{ .AuthAddr }};
		}
	}

	server {
		listen unix:{{ .ProtectedSocket }};
		server_name protected.example.com;

		location = /_internal/auth {
			internal;

			# Send the request to the auth service; nginx only
			# allows 2xx or 4xx responses, so specify the behaviour
			# we want.
			proxy_pass {{ .AuthAddr }}/api/verify?behaviour=deny;

			# auth_request includes headers but not body
			proxy_set_header Content-Length "";
			proxy_pass_request_body         off;

			# Pass original headers to the auth service
			proxy_set_header X-Forwarded-Method $request_method;
			proxy_set_header X-Forwarded-Proto  $scheme;
			proxy_set_header X-Forwarded-Host   $host;
			proxy_set_header X-Forwarded-URI    $request_uri;
			proxy_set_header X-Real-IP          $remote_addr;
		}

		location / {
			root {{ .ProtectedDir }};

			# Authenticate with our internal auth service
			auth_request /_internal/auth;

			# If the auth service returns an error, redirect to the
			# login page
			error_page 403 = @error403;
		}

		location @error403 {
			return 302 http://auth.example.com/login?redirect_uri=$scheme://$host$request_uri;
		}
	}
}
`)))

func TestNginx(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}

	nginxBin := findBinary(t, "nginx")
	bin := buildHomeauth(t)
	ctx, addr := startHomeauth(t, bin, startOptions{
		Domain:    "example.com",
		ServerURL: "http://auth.example.com",
	})

	// Create a nginx config file
	confFile := must.Get(os.Create(filepath.Join(t.TempDir(), "nginx.conf")))
	defer confFile.Close()

	// Create protected directory we serve
	pdir := filepath.Join(t.TempDir(), "protected")
	must.Do(os.Mkdir(pdir, 0755))
	must.Do(os.WriteFile(filepath.Join(pdir, "index.html"), []byte("Super secret"), 0644))

	// Create logs directory
	logDir := filepath.Join(t.TempDir(), "logs")
	must.Do(os.Mkdir(logDir, 0755))

	authSocket := filepath.Join(t.TempDir(), "auth.sock")
	protectedSocket := filepath.Join(t.TempDir(), "protected.sock")

	var configBuf bytes.Buffer
	if err := nginxConfigTemplate.Execute(io.MultiWriter(confFile, &configBuf), map[string]any{
		"AuthAddr":        addr,
		"ProtectedDir":    pdir,
		"AuthSocket":      authSocket,
		"ProtectedSocket": protectedSocket,

		"AccessLog": filepath.Join(logDir, "access.log"),
		"PIDFile":   filepath.Join(t.TempDir(), "nginx.pid"),
	}); err != nil {
		t.Fatalf("failed to execute nginx config template: %v", err)
	}

	defer func() {
		if t.Failed() {
			t.Logf("nginx config:\n%s", configBuf.String())
		}
	}()

	must.Do(confFile.Sync())
	must.Do(confFile.Close())

	// Start nginx
	//
	// NOTE: newer nginx versions have the '-e' option to configure where
	// the error log goes; this takes effect immediately, so we don't get
	// the following spurious error:
	//	could not open error log file: open() "/var/log/nginx/error.log" failed
	//
	// However, this was added in 1.19.5, and we want to support older
	// versions of nginx (e.g. the version installed in the GitHub Actions
	// runner), so we skip this for now.
	proc := testproc.New(t, nginxBin,
		[]string{
			"-g", "daemon off; error_log stderr warn;",
			"-c", confFile.Name(),
		},
		&testproc.Options{
			ShutdownSignal: syscall.SIGTERM,
			LogStdout:      true,
			LogStderr:      true,
			Dir:            t.TempDir(),
		})

	// Wait for it to create the Unix sockets.
	proc.WaitForFiles(time.Second, authSocket, protectedSocket)

	// Create a second context that is canceled when either our original
	// context is, or the nginx process exits.
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
	req := must.Get(http.NewRequestWithContext(proc.Context(), "GET", "http://protected.example.com/index.html", nil))
	resp := must.Get(tt.client.Do(req))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got status %d, want 200", resp.StatusCode)
	}
	if hostname := resp.Request.URL.Hostname(); hostname != "auth.example.com" {
		t.Fatalf("expected redirect to auth service, but got: %v", resp.Request.URL)
	}
	body := must.Get(io.ReadAll(resp.Body))
	if bytes.Contains(body, []byte("Super secret")) {
		t.Fatalf("did not expect to find \"Super secret\" in response")
	}

	// Then log in to homeauth.
	tt.loginPassword("andrew@du.nham.ca", "password")

	// We should be able to make a request to our protected site now, and
	// the verification should work fine.
	req = must.Get(http.NewRequestWithContext(proc.Context(), "GET", "http://protected.example.com/index.html", nil))
	resp = must.Get(tt.client.Do(req))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got status %d, want 200", resp.StatusCode)
	}
	body = must.Get(io.ReadAll(resp.Body))
	if string(body) != "Super secret" {
		t.Fatalf("got body %q, want %q", body, "Super secret")
	}
}
