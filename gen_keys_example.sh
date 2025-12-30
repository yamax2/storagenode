#!/bin/sh

set -e

mkdir -p keys

# node
openssl genrsa -out ./keys/node.pem 2048
./jwks.sh ./keys/node.pem > ./keys/node.jwks

# example nginx configuration
openssl genrsa -out ./keys/server.key 2048
openssl req -new -x509 -sha256 -nodes -days 3650 -key ./keys/server.key -out ./keys/server.crt -config ./keys/openssl.cnf -extensions req_ext

# app
openssl genrsa -out ./keys/application.pem 4096
./jwks.sh ./keys/application.pem > ./keys/application.jwks
