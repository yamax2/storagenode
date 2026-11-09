# storagenode bundle

A self-contained nginx build for armv7 Linux: the nginx binary, the two
dynamic modules the storage node needs, every shared library they link against
(including the musl loader) and an example configuration — all in this single
directory. Nothing is installed system-wide and the directory can be moved
anywhere.

## Configuring

Edit `conf/storagenode.conf` before the first start:

- `server_name`: a name under the app's host. The app's `datasession` cookie is
  set for the app's domain, so a node outside it never receives the cookie and
  every `/data/` read is a 401. Its first name must be exactly the hostname the
  app knows the node by, lowercase: every service token names it in its `host`
  claim, which the node compares to `$server_name`.
- `ssl_certificate` / `ssl_certificate_key`: the node's TLS certificate (see
  below). It is the only key the node holds.
- In `location = /service_public_key`, `$pubkey_host` (the app's host) and a
  `resolver` that can find it. Every token, and the data cookie, is checked
  against the app's JWKS fetched from there, over TLS verified against
  `conf/ca-certificates.crt`, the CA bundle the release ships. Replace that file
  to trust a private CA.
- In `conf/options.conf`, the app's origin, so it may `fetch` from `/data/`.

## Running

```sh
./run.sh -t                  # test the configuration
./run.sh -g 'daemon off;'    # foreground, e.g. under a supervisor
./run.sh                     # daemonize
```

The example listens on 8443 so it needs no root and does not collide with an
appliance web UI already holding 443. To use the standard ports, edit the
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

The example listens on IPv4 only. A `listen [::]:...` line added to
`storagenode.conf` needs a kernel built with IPv6: nginx treats an unsupported
address family as fatal.

## Upgrading from a release with the session module

Earlier bundles shipped `ngx_http_storage_node_session_start_module.so` and
`jwks.sh`, and `run.sh` generated `conf/keys/node.pem` and `node.jwks` on first
boot. None of that is used any more: delete them. If you kept your own
`conf/nginx.conf`, remove its `load_module` line for that module first -- nginx
refuses to start when a `load_module` names a missing `.so`.

Your own `conf/storagenode.conf` has to change too, or nginx refuses to start on
the module's `storage_node_session_start`, or reads a key file you deleted. The
simplest way is to take the new example and copy your `server_name`, certificate
paths, `$pubkey_host` and `resolver` into it. Editing yours instead:

- remove `location /service/start`;
- in `/data/`, read `$cookie_datasession` instead of `$cookie_storagesession`,
  replace `auth_jwt_key_file ./keys/node.jwks` with
  `auth_jwt_key_request /service_public_key jwks;`, and require `scope`;
- in `/service/`, require `host` against `$server_name`;
- point `/service_public_key` at the app's `/.well-known/jwks.json`, with the new
  example's cache, proxy and TLS verification settings, and `inactive=30d` on
  `proxy_cache_path`.

## Letsencrypt cert
use [lego app](https://github.com/go-acme/lego)

```sh
REGRU_USERNAME=nonemx@gmail.com \
REGRU_PASSWORD=... \
HTTPS_PROXY="socks5h://127.0.0.1:8888" \
./lego run -d 'node1.photos2.tretyakov-ma.ru' --email="max@tretyakov-ma.ru" --tls-skip-verify --dns regru \
--dns.propagation.wait 5m --dns.resolvers 1.1.1.1 --dns.resolvers 8.8.8.8
```
