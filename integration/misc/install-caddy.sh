#!/bin/bash

set -euo pipefail

main() {
    APIDATA="$(curl -fsSL https://api.github.com/repos/caddyserver/caddy/releases/latest)"
    DOWNLOAD_URL="$(echo "$APIDATA" | jq -r '.assets[] | select(.name | test("linux_amd64.tar.gz$")) | .browser_download_url')"

    # Fetch the latest version
    curl -Lo /tmp/caddy.tar.gz -fsSL "$DOWNLOAD_URL"

    # Extract the binary
    tar -C /tmp -xzf /tmp/caddy.tar.gz caddy

    # Install the binary to the /usr/local/bin directory; requires root.
    sudo install -m 755 /tmp/caddy /usr/local/bin/caddy
}

main "$@"
