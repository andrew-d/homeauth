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

## Configuration

### OIDC Clients

Add a new entry to the `Clients` key in the database/configuration file. For
example, to test things out with the [OIDC Playground][oplay], you
can use the following example configuration, which contains a user with the
password "password123", and authorizes the OIDC Playground's client ID and
client secret (the keys in this example are the playground's default keys, and
can be changed in the configuration):

```json
{
  "Users": {
    "11111111-2222-3333-4444-555555555555": {
      "UUID": "11111111-2222-3333-4444-555555555555",
      "Email": "test@example.com",
      "PasswordHash": "$argon2id$v=19$m=524288,t=2,p=2$LFoLcUjj47J+8rFKTkV2Vw$cETlZXupXaGj+kuweaU8mA"
    }
  },
  "Config": {
    "CookieDomain": "localhost",
    "Clients": {
      "kbyuFDidLLm280LIwVFiazOqjO3ty8KH": {
        "Name": "openidconnect.net",
        "ClientID": "kbyuFDidLLm280LIwVFiazOqjO3ty8KH",
        "ClientSecret": "60Op4HFM0I8ajz0WdiStAbziZ-VFQttXuxixHHs2R7r7-CW8GR79l-mmLqMhc-Sa",
        "RedirectURIs": [
          "https://openidconnect.net/callback"
        ]
      }
    }
  }
}
```

[oplay]: https://openidconnect.net

### Generating Password Hashes

There is a `./cmd/genpassword` command that can be used to generate password
hashes for users. For example, to generate a password hash for the password
"password123", you can run the following command:

```shell
$ go build ./cmd/genpassword
$ ./genpassword password123
```

The utility also offers the `-stdin` flag, which will read the password from
stdin. This can be useful for scripting, or for securely entering a password
without it being stored in your shell history.
