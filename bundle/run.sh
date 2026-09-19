#!/bin/sh
# Launcher for the self-contained storagenode nginx bundle.
#
# The binary and its modules are linked against the musl libraries shipped in
# this directory, so we invoke the bundled loader explicitly instead of relying
# on the interpreter path baked into the ELF header. That is what makes the
# bundle work on any armv7 Linux, musl- or glibc-based.
#
# Usage: ./run.sh [-c <config>] [extra nginx arguments]
#   ./run.sh -t                  test the configuration
#   ./run.sh -g 'daemon off;'    run in the foreground

set -eu

DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
CONF="$DIR/conf/nginx.conf"

if [ "${1:-}" = "-c" ]; then
  shift
  CONF=$1
  shift
fi

mkdir -p "$DIR/tmp" "$DIR/logs" "$DIR/data/files" "$DIR/data/cache"

# Started as root, nginx drops worker privileges to its compiled-in default,
# nobody:nobody, and aborts with getgrnam() if that pair does not exist -- it
# does not on Debian (nobody:nogroup) nor on much appliance firmware. Pick a
# pair that is actually present, unless the config already chose one, the caller
# passes its own -g, or STORAGENODE_USER overrides (e.g. "www-data www-data").
if [ "$(id -u)" = 0 ] && ! grep -qE '^[[:space:]]*user[[:space:]]' "$CONF"; then
  creds=${STORAGENODE_USER:-}
  if [ -z "$creds" ]; then
    for cand in nobody:nogroup nobody:nobody daemon:daemon; do
      u=${cand%%:*}
      g=${cand##*:}
      if grep -q "^$u:" /etc/passwd 2>/dev/null && grep -q "^$g:" /etc/group 2>/dev/null; then
        creds="$u $g"
        break
      fi
    done
  fi

  if [ -n "$creds" ]; then
    case " $* " in
      *" -g "*) ;;
      *) set -- -g "user $creds;" "$@" ;;
    esac
  fi
fi

LOADER=$(ls "$DIR"/ld-musl-*.so.1 2>/dev/null | head -n1 || true)

if [ -n "$LOADER" ]; then
  exec "$LOADER" --library-path "$DIR" "$DIR/nginx" -p "$DIR/" -c "$CONF" "$@"
fi

LD_LIBRARY_PATH="$DIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export LD_LIBRARY_PATH
exec "$DIR/nginx" -p "$DIR/" -c "$CONF" "$@"
