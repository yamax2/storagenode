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

# generating keys. Absolute paths throughout: a boot hook runs with an
# arbitrary working directory, and no 'exec' -- that would replace this shell
# and nginx would never be reached on the run that creates the keys.
if [ ! -f "$DIR/conf/keys/node.pem" ]; then
  openssl genrsa -out "$DIR/conf/keys/node.pem" 2048
  "$DIR/jwks.sh" "$DIR/conf/keys/node.pem" > "$DIR/conf/keys/node.jwks"
fi

# start. The binary's PT_INTERP is /lib/ld-musl-armhf.so.1, which exists on
# Alpine but not on appliance firmware, and the kernel resolves it before any
# loader or LD_LIBRARY_PATH gets a say -- so the bundled loader is not a
# fallback, it is the only way in. Missing loader fails here, loudly, rather
# than as an ENOENT from execve that every shell reports as "not found".
LOADER=$(ls "$DIR"/ld-musl-*.so.1 2>/dev/null | head -n1 || true)
[ -n "$LOADER" ] || { echo "$0: no ld-musl-*.so.1 alongside $DIR/nginx" >&2; exit 1; }
exec "$LOADER" --library-path "$DIR" "$DIR/nginx" -p "$DIR/" -c "$DIR/conf/nginx.conf" "$@"
