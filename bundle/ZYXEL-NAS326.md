# Running the bundle on a Zyxel NAS326

The NAS326 is a single-core Marvell Armada 380 (ARMv7-A, Cortex-A9, VFPv3), so
the armv7 bundle runs on it as-is. What the box does *not* give you is a normal
init system: `/etc`, `/usr/bin` and the rest of the root filesystem are
recreated from the firmware image on every boot, so anything you drop there is
gone after a restart. The only writable, persistent storage is the data volume
under `/i-data/`, and the firmware has exactly one supported hook for running
your own code from there at boot.

This document covers that hook: writing the init script, and registering it.
It assumes the bundle is already on the volume and `./run.sh -t` passes.

---

## 1. The init script

The firmware executes your script with **`startup`** at boot and **`shutdown`**
at halt — *not* the conventional `start`/`stop`. A script that only understands
`start` will print its usage line and exit 1 at boot, which is the single most
common reason "my script is registered but nothing runs". The script below
accepts both spellings so the same file works when you test it by hand.

There is one more firmware quirk worth knowing, because it looks like
superstition otherwise: **the file must contain the literal string `/i-data/`
somewhere in its contents.** The controller that launches these scripts falls
back to `/etc/init.d/<name>` when it does not find that string, and that path
does not exist, so the script silently never runs. Any line containing it
counts — a comment is enough. In the script below the real paths already
contain it, and the comment on line 2 guarantees it.

Create `/i-data/.system/zy-pkgs/storagenode.sh` with this content:

```sh
#!/bin/sh
# /i-data/ - the Zyxel package controller requires this literal string in the file.
#
# Boot hook for the storagenode nginx bundle.
# Invoked as: storagenode.sh startup|shutdown  (start|stop accepted for manual use)

BUNDLE=/i-data/5c1d0068/node-ekb
LOG=$BUNDLE/logs/boot.log

log() { echo "$(date '+%Y-%m-%d %H:%M:%S') $*" >> "$LOG"; }

start() {
    [ -x "$BUNDLE/run.sh" ] || { log "run.sh missing or not executable"; exit 1; }
    mkdir -p "$BUNDLE/logs"
    log "starting storagenode"
    # run.sh daemonizes nginx itself, so no trailing '&' is needed.
    "$BUNDLE/run.sh" >> "$LOG" 2>&1
    log "run.sh exited with $?"
}

stop() {
    log "stopping storagenode"
    "$BUNDLE/run.sh" -s quit >> "$LOG" 2>&1 || kill $(cat "$BUNDLE/nginx.pid" 2>/dev/null) 2>/dev/null
}

case "$1" in
    startup|start)   start ;;
    shutdown|stop)   stop ;;
    restart)         stop; sleep 2; start ;;
    status)          [ -f "$BUNDLE/nginx.pid" ] && kill -0 $(cat "$BUNDLE/nginx.pid") 2>/dev/null \
                         && echo "running" || echo "stopped" ;;
    *)               echo "Usage: $0 {startup|shutdown|restart|status}"; exit 1 ;;
esac

exit 0
```

Then make it executable — the controller skips files without the bit:

```sh
chmod +x /i-data/.system/zy-pkgs/storagenode.sh
```

Adjust `BUNDLE` to wherever the bundle actually lives. `/i-data/` holds one
directory per volume named after its UUID, plus a `sysvol` symlink to the
internal one — check with `ls -la /i-data/` rather than copying the path above.

Why it is written this way:

- **`$BUNDLE` is absolute.** At boot the script runs as root from an
  unpredictable working directory with a minimal `PATH` and no `HOME`. Nothing
  relative is safe. `run.sh` itself resolves its own directory, so as long as
  you call it by an absolute path the rest of the bundle locates correctly.
- **Everything is logged to a file.** Boot-time stdout goes nowhere on this
  firmware; without the redirect a failure is invisible.
- **Stop goes through nginx, not `killall`.** `run.sh -s quit` passes the signal
  to the same binary with the same prefix and config, which drains connections;
  `killall nginx` would also hit any unrelated nginx and skips the graceful
  shutdown. The `kill` on the pidfile is only a fallback.
- **No `&`.** `run.sh` execs nginx without `daemon off`, so nginx backgrounds
  itself and `run.sh` returns immediately. Adding `&` would be harmless but
  pointless — and if you ever switch to `-g 'daemon off;'`, you must add it,
  otherwise the boot sequence blocks forever.

Sanity-check the syntax and then run it by hand before rebooting:

```sh
sh -n /i-data/.system/zy-pkgs/storagenode.sh
/i-data/.system/zy-pkgs/storagenode.sh startup
/i-data/.system/zy-pkgs/storagenode.sh status
```

## 2. Register it

The firmware's `zypkg_controller.sh` reads one file at boot,
`/i-data/.system/zy-pkgs/USRPKG_DEPS_START`. Each line is treated as a
filename: the directory part is stripped, `/i-data/.system/zy-pkgs/` is
prepended, and if the result is executable it is run with `startup`. The file
does not exist on a fresh system — create it:

```sh
echo storagenode.sh >> /i-data/.system/zy-pkgs/USRPKG_DEPS_START
cat /i-data/.system/zy-pkgs/USRPKG_DEPS_START
```

For the shutdown side, list the same script in `USRPKG_DEPS_SHUTDOWN`:

```sh
echo storagenode.sh >> /i-data/.system/zy-pkgs/USRPKG_DEPS_SHUTDOWN
```

One name per line, bare filenames, no `./`, no arguments, and make sure the
file ends with a newline.

Then reboot and verify:

```sh
reboot
# ... wait for the box, ssh back in ...
ps | grep [n]ginx
tail -20 /i-data/sysvol/storagenode/bundle/logs/boot.log
tail -20 /i-data/sysvol/storagenode/bundle/logs/error.log
```

**To disable autostart**, remove the line from `USRPKG_DEPS_START` (or
`chmod -x` the script). Nothing else references it.

### Alternative hook

Some firmware builds also run every executable in
`/usr/local/zy-pkgs/etc/init.d/` with `startup`/`shutdown` — that directory is a
symlink into the data volume, so it persists too. It is the same mechanism from
the other end and the same script works there. Use it only if
`USRPKG_DEPS_START` turns out not to fire on your firmware version; do not
register the script in both places, or it will be started twice.

---

## Troubleshooting

| Symptom | Cause |
|---|---|
| Nothing runs at boot, no log file | Script not executable, or missing the literal `/i-data/` string, or the name in `USRPKG_DEPS_START` does not match the filename exactly |
| `boot.log` shows only the usage line | Firmware passed `startup` to a script that only handles `start` |
| Works by hand, fails at boot | Relative path, or a command that is not in the boot-time `PATH` — use absolute paths for everything |
| `not found` on a script that exists | CRLF line endings: `sed -i 's/\r$//' <file>` |
| nginx exits immediately at boot, fine manually | Check `logs/error.log`: usually a port already taken by the web UI, or a `listen [::]` line on a kernel without IPv6 (nginx treats that as fatal) |
| Everything disappears after a firmware upgrade | `/i-data/` survives upgrades, `/etc` does not — re-check that you edited only files under `/i-data/` |

## References

- [NAS326, auto execute command at startup — Zyxel Community](https://community.zyxel.com/en/discussion/12557/nas326-auto-execute-command-at-startup)
- [How to start a custom service on the NAS 325 v2 — Zyxel Community](https://community.zyxel.com/en/discussion/7325/how-to-start-a-custom-service-on-the-nas-325-v2)
- [Zyxel utils — NAS-Central Zyxel Wiki](http://zyxel.nas-central.org/wiki/Zyxel_utils)
