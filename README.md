# homeauth

> [!WARNING]
> This project is still in the early stages of development and is not yet
> considered secure. Use at your own risk.

`homeauth` is a basic identity provider for small homelab-style setups. It is
designed to be a simple, easy-to-use and easy-to-configure alternative to
heavier identity providers.

All configuration and data is stored in a single JSON file for ease-of-use, and
the server is designed to be run behind a reverse proxy that handles TLS
termination.

## Features

- OIDC Identity Provider
- Log in with WebAuthn, including support for multiple WebAuthn devices
- Log in via magic link, when SMTP credentials are configured
- Multi-user support
- No database required; all data is stored in a single JSON file
- Very well-tested
- Support for `auth_request` in Nginx / `forward_auth` in Caddy/Traefik, so you
  can use this as an authentication provider for other services behind a
  reverse proxy

### Anti-Features

- No high availability; this is designed for small, homelab-style setups where
  a single instance is sufficient
- No sharding; all data is stored in a single JSON file
- No synchronization (LDAP, SCIM, etc.)
- No support for multiple realms or tenants
- No fancy JavaScript UI; this is a server-side rendered application, with
  minimal JavaScript and no frameworks, JavaScript build system, etc.

## Usage

There's a basic example configuration in `homeauth.example.json` that you can
use as a starting point; copy it to `homeauth.json` and modify as appropriate.
You can then run `homeauth` with the following command:

```shell
$ go build ./cmd/homeauth
$ ./homeauth \
    --db homeauth.json \
    --server-url https://auth.example.com
```

The `--server-url` flag is used to specify the URL that the server is running
on. This is used to generate the redirect URLs for the OAuth2 flow, to set the
WebAuthn origin, and a varity of other things; it should be the service that
users of this IdP access (e.g. behind a load balancer that does TLS).

You can configure the port that the server listens on with the `--port` flag,
independent of the `--server-url` flag.
