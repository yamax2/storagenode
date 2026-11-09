#!/bin/sh
# The node's TLS certificate, self-signed, for the names in keys/openssl.cnf.
# It is the only key a node holds: tokens and the data cookie are checked
# against the app's JWKS, so there is nothing else to generate.

set -e

mkdir -p keys

if [ ! -f ./keys/server.key ]; then
    openssl genrsa -out ./keys/server.key 2048
fi

# Reissued from the same key whenever openssl.cnf has changed since: a kept
# certificate would go on naming hosts the config no longer serves, and browsers
# would refuse every image from the node on a name mismatch.
if [ ! -f ./keys/server.crt ] || [ ./keys/openssl.cnf -nt ./keys/server.crt ]; then
    openssl req -new -x509 -sha256 -nodes -days 3650 -key ./keys/server.key -out ./keys/server.crt -config ./keys/openssl.cnf -extensions req_ext
fi
