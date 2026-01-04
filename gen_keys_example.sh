#!/bin/sh

set -e

mkdir -p keys

# node
if [ ! -f ./keys/node.pem ]; then
    openssl genrsa -out ./keys/node.pem 2048
fi

./jwks.sh ./keys/node.pem > ./keys/node.jwks

# example nginx configuration
if [ ! -f ./keys/server.key ]; then
    openssl genrsa -out ./keys/server.key 2048
    openssl req -new -x509 -sha256 -nodes -days 3650 -key ./keys/server.key -out ./keys/server.crt -config ./keys/openssl.cnf -extensions req_ext
fi

# app
if [ ! -f ./keys/application.pem ]; then
    openssl genrsa -out ./keys/application.pem 4096
fi

./jwks.sh ./keys/application.pem > ./keys/application.jwks
