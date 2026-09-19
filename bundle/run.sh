#!/bin/sh
# Launcher for the self-contained storagenode nginx bundle.
#
# The binary and its modules are linked against the musl libraries shipped in
# this directory, so we invoke the bundled loader explicitly instead of relying
# on the interpreter path baked into the ELF header. That is what makes the
# bundle work on any armv7 Linux, musl- or glibc-based.
#
# Usage: ./run.sh [extra nginx arguments]
#   ./run.sh -t                  test the configuration
#   ./run.sh -g 'daemon off;'    run in the foreground

set -eu

DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
mkdir -p "$DIR/tmp" "$DIR/logs" "$DIR/data/files" "$DIR/data/cache" "$DIR/conf/keys"

# generating keys
if [ ! -f "$DIR/conf/keys/node.pem" ]; then
  openssl genrsa -out ./conf/keys/node.pem 2048
  exec "$DIR/jwks.sh" "$DIR/conf/keys/node.pem" > "$DIR/conf/keys/node.jwks"
fi

# start
LOADER=$(ls "$DIR"/ld-musl-*.so.1 2>/dev/null | head -n1 || true)
if [ -n "$LOADER" ]; then
  exec "$LOADER" --library-path "$DIR" "$DIR/nginx" -p "$DIR/" -c "$DIR/conf/nginx.conf" "$@"
fi

LD_LIBRARY_PATH="$DIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export LD_LIBRARY_PATH
exec "$DIR/nginx" -p "$DIR/" -c "$DIR/conf/nginx.conf" "$@"
