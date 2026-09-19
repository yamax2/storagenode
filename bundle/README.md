# storagenode bundle

A self-contained nginx build for armv7 Linux: the nginx binary, the three
dynamic modules the storage node needs, every shared library they link against
(including the musl loader) and an example configuration in `conf/`. Nothing is
installed system-wide and the directory can be moved anywhere.

## Contents

| File | Purpose |
| --- | --- |
| `nginx` | nginx binary, built with the dynamic-module ABI |
| `ngx_http_auth_jwt_module.so` | [kjdev/nginx-auth-jwt](https://github.com/kjdev/nginx-auth-jwt) |
| `ngx_http_dav_ext_module.so` | [yamax2/nginx-dav-ext-module](https://github.com/yamax2/nginx-dav-ext-module) (PROPFIND checksums) |
| `ngx_http_storage_node_session_start_module.so` | session-start module from this repository |
| `ld-musl-*.so.1`, `lib*.so*` | runtime libraries, loaded from this directory only |
| `conf/nginx.conf` | example main configuration |
| `conf/storagenode.conf` | example server blocks, included by `nginx.conf` |
| `conf/options.conf` | example CORS headers, included by `storagenode.conf` |
| `conf/mime.types` | stock nginx MIME map |
| `conf/keys/` | TLS certificate, node signing key and the JWKS files (you supply) |
| `run.sh` | launcher that wires up the loader and the prefix |
| `jwks.sh` | derives a JWKS from an RSA private key |
| `VERSION.nginx` | nginx version this bundle was built from |

## Layout expected at runtime

```
conf/        the example configuration (shipped)
conf/keys/   server.crt, server.key, node.pem, node.jwks, application.jwks
data/files/  files served over WebDAV
data/cache/  proxy cache (created by run.sh)
logs/        access.log and error.log (created by run.sh)
tmp/         nginx temporary files (created by run.sh)
```

Generate a set of development keys with `gen_keys_example.sh` from the
repository and copy the result into `conf/keys/`. `jwks.sh` is the same script
the repository uses, shipped here so a node can rebuild its JWKS in place:

```sh
./jwks.sh conf/keys/node.pem > conf/keys/node.jwks
```

`conf/keys/` holds private keys, so keep it readable only by the nginx worker
user: `chmod 700 conf/keys` once the bundle runs as a dedicated user.

### Two base directories

Paths in the configuration are relative, but nginx resolves them against one of
two bases, which matters now that the configuration sits in `conf/`:

| Resolved against the prefix (this directory) | Resolved against `conf/` |
| --- | --- |
| `load_module`, `root`, `alias`, `proxy_cache_path`, `error_log`, `access_log`, `pid`, `*_temp_path` | `include`, `ssl_certificate`, `ssl_certificate_key`, `auth_jwt_key_file` |

The keys live in `conf/keys/`, so the right-hand column reaches them as
`keys/server.crt` while the left-hand one has to spell out `conf/keys` — both
name the same directory. Adding a key or certificate path? Check which column
the directive is in first.

`storage_node_session_start` is a third case: the module opens its key itself,
relative to the working directory nginx was started in, so run `run.sh` from
this directory (or make the path absolute).

## Running

```sh
./run.sh -t                  # test the configuration
./run.sh -g 'daemon off;'    # foreground, e.g. under a supervisor
./run.sh                     # daemonize
```

The example listens on 8080/8443 so it needs no root and does not collide with
an appliance web UI already holding 80/443. To use the standard ports, edit the
`listen` directives in `conf/storagenode.conf` and either run as root or grant
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
`conf/storagenode.conf`; nginx treats an unsupported address family as fatal.

## systemd

```ini
[Unit]
Description=storagenode
After=network.target

[Service]
WorkingDirectory=/opt/storagenode
ExecStart=/opt/storagenode/run.sh -g 'daemon off;'
ExecReload=/opt/storagenode/run.sh -s reload
Restart=on-failure

[Install]
WantedBy=multi-user.target
```
