# Running the bundle on a Zyxel NAS326

The NAS326 is a single-core Marvell Armada 380 (ARMv7-A, Cortex-A9, VFPv3), so
the armv7 bundle runs on it as-is. What the box does *not* give you is a normal
init system: `/etc`, `/usr/bin` and the rest of the root filesystem are
recreated from the firmware image on every boot, so anything you drop there is
gone after a restart. The only writable, persistent storage is the data volume
under `/i-data/`, and the firmware has essentially one hook for running your
own code from there at boot (a second one, honoured by some builds, is noted in
section 2).

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
ROTATE_PID=$BUNDLE/logs/rotator.pid
MAXSIZE=${MAXSIZE:-10485760}    # rotate a log once it grows past 10 MB
KEEP=7                          # generations to keep

log() { echo "$(date '+%Y-%m-%d %H:%M:%S') $*" >> "$LOG"; }

# A pidfile on the data volume outlives a power cut, and after the reboot that
# number may belong to some system daemon -- never signal it unchecked.
# Sets $pid on success.
pid_alive() {   # pid_alive <pidfile> <pattern expected in /proc/PID/cmdline>
    pid=$(cat "$1" 2>/dev/null)
    [ -n "$pid" ] && grep -qs "$2" "/proc/$pid/cmdline"
}

start() {
    [ -x "$BUNDLE/run.sh" ] || { log "run.sh missing or not executable"; exit 1; }
    mkdir -p "$BUNDLE/logs"
    log "starting storagenode"
    # run.sh daemonizes nginx itself, so no trailing '&' is needed.
    "$BUNDLE/run.sh" >> "$LOG" 2>&1
    rc=$?
    log "run.sh exited with $rc"
    [ "$rc" -eq 0 ] || return 1
    rotator_start
}

stop() {
    log "stopping storagenode"
    rotator_stop
    if pid_alive "$BUNDLE/nginx.pid" nginx; then
        "$BUNDLE/run.sh" -s quit >> "$LOG" 2>&1 || kill "$pid" 2>/dev/null
    else
        log "no live nginx behind nginx.pid, nothing to stop"
        rm -f "$BUNDLE/nginx.pid"
    fi
}

# nginx keeps writing to the old inode after a rename, so every rotation has to
# be followed by exactly one 'reopen' -- and only then is it safe to compress.
rotate() {
    rotated=
    for f in "$BUNDLE/logs/access.log" "$BUNDLE/logs/error.log" "$LOG"; do
        [ -f "$f" ] || continue
        [ "$(wc -c < "$f")" -ge "$MAXSIZE" ] || continue

        rm -f "$f.$KEEP.gz" "$f.$KEEP"
        i=$KEEP
        while [ "$i" -gt 1 ]; do
            j=$((i - 1))
            # .gz normally; the plain name only if gzip was unavailable
            [ -f "$f.$j.gz" ] && mv "$f.$j.gz" "$f.$i.gz"
            [ -f "$f.$j" ] && mv "$f.$j" "$f.$i"
            i=$j
        done
        mv "$f" "$f.1"
        rotated="$rotated $f.1"
    done

    [ -n "$rotated" ] || return 0

    "$BUNDLE/run.sh" -s reopen >/dev/null 2>&1
    sleep 1
    for f in $rotated; do
        gzip -f "$f" 2>/dev/null || true
    done
    log "rotated:$rotated"
}

rotator_start() {
    rotator_stop
    ( while :; do sleep 3600; rotate; done ) &
    echo $! > "$ROTATE_PID"
}

rotator_stop() {
    pid_alive "$ROTATE_PID" storagenode.sh && kill "$pid" 2>/dev/null
    rm -f "$ROTATE_PID"
}

case "$1" in
    startup|start)   start ;;
    shutdown|stop)   stop ;;
    restart)         stop; sleep 2; start ;;
    rotate)          rotate ;;
    status)          pid_alive "$BUNDLE/nginx.pid" nginx && echo "running" || echo "stopped" ;;
    *)               echo "Usage: $0 {startup|shutdown|restart|rotate|status}"; exit 1 ;;
esac

exit $?
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
- **No pidfile is trusted on its own.** Both pidfiles live on the data volume,
  so they outlive a power cut — and after the reboot the PID they name may
  belong to a system daemon, which the hook would then signal as root. nginx's
  own `-s quit` does not validate the pidfile either, so `pid_alive` checks
  `/proc/<pid>/cmdline` before anything is signalled or reported as running.
- **Rotation is part of the hook.** There is no `logrotate` and no persistent
  crontab on this firmware, so the script carries its own rotator, started only
  once nginx is actually up and stopped again by `shutdown`. See section 3.
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
tail -20 /i-data/5c1d0068/node-ekb/logs/boot.log
tail -20 /i-data/5c1d0068/node-ekb/logs/error.log
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

## 3. Log rotation

`access.log` and `error.log` grow without bound — nginx never rotates them
itself, and on this firmware nothing else will either. There is no `logrotate`
binary, and BusyBox `crond` keeps its crontabs under `/var/spool/cron/crontabs/`
on the ramdisk, so a `crontab -e` entry is gone after the next reboot. The boot
hook is the only persistent place to put this, so the script above carries its
own rotator.

`rotator_start` forks a loop that calls `rotate` every hour and writes the
loop's PID to `logs/rotator.pid`, so `shutdown` can kill it and a restart never
leaves two rotators running. `rotate` is a no-op unless a log has passed
`MAXSIZE` (10 MB), so the hourly wake-up costs nothing on a quiet box while a
busy one gets trimmed promptly instead of at a fixed hour.

The order inside `rotate` is the part that matters:

1. Shift `access.log.1.gz` → `.2.gz` → … and drop generation `$KEEP`.
2. `mv access.log access.log.1`. nginx holds the file by inode, so it keeps
   writing into the renamed file — nothing is lost yet, and nothing appears in
   a new `access.log` either.
3. `run.sh -s reopen`, once, after *all* the renames. That sends `SIGUSR1` to
   the master through the bundle's own prefix and pidfile; nginx closes the old
   descriptors and creates fresh log files.
4. Only then `gzip` the `.1` files. Compressing before the reopen would
   compress a file nginx is still appending to.

Tune `MAXSIZE` and `KEEP` at the top of the script. The ceiling is per log
file, and `rotate` covers three of them (`access.log`, `error.log`,
`boot.log`): seven 10 MB generations each is ~210 MB worst case before
compression, and a good deal less once gzipped.

Test it without waiting for the threshold — `MAXSIZE` is overridable from the
environment for exactly this:

```sh
MAXSIZE=1 /i-data/.system/zy-pkgs/storagenode.sh rotate
ls -l /i-data/5c1d0068/node-ekb/logs/
```

The new `access.log` must start growing again on the next request. If it stays
at 0 bytes while requests are served, the reopen did not reach the master:
check `logs/boot.log` and that `nginx.pid` holds the PID of a live process.

## References

- [NAS326, auto execute command at startup — Zyxel Community](https://community.zyxel.com/en/discussion/12557/nas326-auto-execute-command-at-startup)
- [How to start a custom service on the NAS 325 v2 — Zyxel Community](https://community.zyxel.com/en/discussion/7325/how-to-start-a-custom-service-on-the-nas-325-v2)
- [Zyxel utils — NAS-Central Zyxel Wiki](http://zyxel.nas-central.org/wiki/Zyxel_utils)
