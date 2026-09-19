# storagenode bundle

A self-contained nginx build for armv7 Linux: the nginx binary, the three
dynamic modules the storage node needs, every shared library they link against
(including the musl loader) and an example configuration — all in this single
directory. Nothing is installed system-wide and the directory can be moved
anywhere.

## Running

```sh
./run.sh -t                  # test the configuration
./run.sh -g 'daemon off;'    # foreground, e.g. under a supervisor
./run.sh                     # daemonize
```

The example listens on 8080/8443 so it needs no root and does not collide with
an appliance web UI already holding 80/443. To use the standard ports, edit the
`listen` directives in `storagenode.conf` and either run as root or grant
`setcap cap_net_bind_service=+ep ./nginx`.

To run a different configuration: `./run.sh -c /path/to/nginx.conf`. Keep using
`run.sh` rather than calling `./nginx` directly — invoked on its own the binary
looks for its libraries in system locations, which is exactly what this bundle
avoids.

## Old kernels

The binary talks to the kernel through the bundled musl loader, not through the
system C library, so the age of the host userland does not matter. Linux 3.10
(typical NAS and router firmware) is fine: `getrandom` is missing there, so
OpenSSL falls back to `/dev/urandom`, and musl falls back from its 64-bit time
syscalls to the legacy ones -- correct until 2038.

The CPU must be ARMv7-A with hardware floating point (VFPv3-D16 or better),
which covers Cortex-A7/A8/A9/A15 and later. Check with `readelf -A ./nginx`
against `/proc/cpuinfo`.

If the kernel was built without IPv6, comment out the `listen [::]:...` lines in
`storagenode.conf`; nginx treats an unsupported address family as fatal.


## Letsencrypt cert
use [lego app](https://github.com/go-acme/lego)

```sh
REGRU_USERNAME=nonemx@gmail.com \
REGRU_PASSWORD=... \
HTTPS_PROXY="socks5h://127.0.0.1:8888" \
./lego run -d 'home.tretyakov-ma.ru' --email="max@tretyakov-ma.ru" --tls-skip-verify --dns regru \
--dns.propagation.wait 5m --dns.resolvers 1.1.1.1 --dns.resolvers 8.8.8.8
```
