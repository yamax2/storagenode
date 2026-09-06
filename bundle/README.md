# storagenode bundle

A self-contained nginx build for armv7 Linux: the nginx binary, the three
dynamic modules the storage node needs, every shared library they link against
(including the musl loader) and an example configuration — all in this single
directory. Nothing is installed system-wide and the directory can be moved
anywhere.

## Contents

| File | Purpose |
| --- | --- |
| `nginx` | nginx binary, built with the dynamic-module ABI |
| `ngx_http_auth_jwt_module.so` | [kjdev/nginx-auth-jwt](https://github.com/kjdev/nginx-auth-jwt) |
| `ngx_http_dav_ext_module.so` | [yamax2/nginx-dav-ext-module](https://github.com/yamax2/nginx-dav-ext-module) (PROPFIND checksums) |
| `ngx_http_storage_node_session_start_module.so` | session-start module from this repository |
| `ld-musl-*.so.1`, `lib*.so*` | runtime libraries, loaded from this directory only |
| `nginx.conf` | example main configuration |
| `storagenode.conf` | example server blocks, included by `nginx.conf` |
| `options.conf` | example CORS headers, included by `storagenode.conf` |
| `mime.types` | stock nginx MIME map |
| `run.sh` | launcher that wires up the loader and the prefix |
| `VERSION.nginx` | nginx version this bundle was built from |

## Layout expected at runtime

All paths in the example configuration are relative to this directory, which
`run.sh` passes to nginx as its prefix:

```
keys/        server.crt, server.key, node.pem, node.jwks, application.jwks
data/files/  files served over WebDAV
data/cache/  proxy cache (created by run.sh)
logs/        access.log and error.log (created by run.sh)
tmp/         nginx temporary files (created by run.sh)
```

Generate a set of development keys with `gen_keys_example.sh` from the
repository and copy the result into `keys/`.

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

## Everything 404s

When nginx runs as root it drops worker privileges, so the worker has to be able
to traverse into this directory and read `keys/` and `data/files/`. If it
cannot, requests come back as 404 and `logs/error.log` shows

```
[crit] stat() ".../keys/application.jwks" failed (13: Permission denied)
```

which names the file even though the problem is usually a parent directory --
a bundle unpacked under `/root`, or one whose own mode is 0700. Check the whole
path with `namei -l $(pwd)/keys/application.jwks` and fix with `chmod 755` on
the offending directory, or run nginx as a user that already has access.

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

## systemd

```ini
[Unit]
Description=storagenode
After=network.target

[Service]
ExecStart=/opt/storagenode/run.sh -g 'daemon off;'
ExecReload=/opt/storagenode/run.sh -s reload
Restart=on-failure

[Install]
WantedBy=multi-user.target
```
