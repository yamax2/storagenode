# About
Containerized Nginx-based WebDAV file server with dual-layer JWT authentication.

| `/service/*` | `/data/*` |
|--------------|-----------|
| File operations (PUT/DELETE/MKCOL/PROPFIND) and clients' downloads (GET) | Read-only access (GET/HEAD) |
| Per-request token (`X-Session-Token` header) | The app's data cookie (`datasession`) |
| Checked against the app's JWKS | Checked against the app's JWKS |

Both are signed by the application, and the node verifies them against the
public keys the app publishes at `/.well-known/jwks.json`, fetched and cached
through the internal `/service_public_key` location. The node holds no secret
of its own -- only its TLS certificate.

Based on:
* [nginx-auth-jwt](https://github.com/kjdev/nginx-auth-jwt) - JWT validation
* [nginx-dav-ext-module](https://github.com/yamax2/nginx-dav-ext-module) - WebDAV protocol, forked to add `md5`/`sha256` PROPFIND properties

# Service endpoint

## Authentication
The `/service/` endpoint requires a JWT token in the `X-Session-Token` header. The token must be RS256-signed and contain:

| Claim | Description | Example |
|-------|-------------|---------|
| `method` | HTTP method being performed | `"PUT"`, `"DELETE"`, `"MKCOL"` |
| `uri` | Full request URI | `"/service/dir1/file.txt"` |
| `host` | The node's hostname: its first `server_name`, lowercase, without a port | `"node1.photos.example.com"` |
| `exp` | Expiration timestamp (Unix) | `1735084800` |

One keyset signs for every node, so `host` is what keeps a token minted for one
node from working on another. The node compares it to its own `server_name`
(`$server_name`), never to the request's `Host` header: the client chooses that
one, and a node that is its server's `default_server` answers whatever it says.

The examples below talk to the Docker template's node,
`node1.application.localhost` (see [Setup](#setup)), so their `$TOKEN` has to name
it. `-k` accepts the self-signed certificate `gen_keys_example.sh` makes.

`GET` is accepted too: a download link handed to a client (a backup tool, say)
reads a file through `/service/` with a token like any other.

## Generate JWT (Ruby)
```ruby
require 'jwt'
require 'openssl'

# The app's private key; its public half is what the app's JWKS publishes.
key = OpenSSL::PKey::RSA.new(File.read('app.pem'))

payload = {
  'method' => 'PUT',
  'uri' => '/service/myfile.txt',
  'host' => 'node1.application.localhost',
  'exp' => Time.now.to_i + 60
}

token = JWT.encode(payload, key, 'RS256', kid: '<the key\'s kid in the JWKS>')
```

Using JWK from config (some of my apps):
```ruby
jwk = App.config.dig(:secure_edge, :telemetry_portals, :jwk)
payload = {'method' => 'DELETE', 'uri' => '/service/dir1/', 'host' => 'node1.application.localhost', 'exp' => Time.now.to_i + 60}
puts JWT.encode(payload, jwk.signing_key, jwk[:alg], kid: jwk[:kid])
```

## Operations

### Create a directory
```sh
curl -k -X MKCOL 'https://node1.application.localhost/service/dir1/' \
  -H "X-Session-Token: $TOKEN"
```
Note: not recursive, parent must exist

### Delete a file/dir
```sh
curl -k -X DELETE 'https://node1.application.localhost/service/dir1/' \
  -H "X-Session-Token: $TOKEN"
```
Note: use trailing slash for directories

### Upload a file
```sh
curl -k -X PUT 'https://node1.application.localhost/service/dir1/test.txt' \
  -H "X-Session-Token: $TOKEN" \
  -T ./test.txt
```

### Get file properties
```sh
curl -k -X PROPFIND 'https://node1.application.localhost/service/dir1/test.txt' \
  -H "X-Session-Token: $TOKEN"
```
response:
```xml
<?xml version="1.0" encoding="utf-8" ?>
<D:multistatus xmlns:D="DAV:">
<D:response>
<D:href>/test/dir1/test.txt</D:href>
<D:propstat>
<D:prop>
<D:displayname>test.txt</D:displayname>
<D:getcontentlength>22</D:getcontentlength>
<D:getlastmodified>Mon, 16 Jun 2025 08:41:54 GMT</D:getlastmodified>
<D:resourcetype></D:resourcetype>
<D:lockdiscovery/>
<D:supportedlock>
</D:supportedlock>
</D:prop>
<D:status>HTTP/1.1 200 OK</D:status>
</D:propstat>
</D:response>
</D:multistatus>
```
### List files
```sh
curl -k -X PROPFIND -H 'Depth: 1' 'https://node1.application.localhost/service/dir1/' \
  -H "X-Session-Token: $TOKEN"
```
response:
```xml
<?xml version="1.0" encoding="utf-8" ?>
<D:multistatus xmlns:D="DAV:">
<D:response>
<D:href>/test/dir1</D:href>
<D:propstat>
<D:prop>
<D:displayname>dir1</D:displayname>
<D:getlastmodified>Mon, 16 Jun 2025 08:41:54 GMT</D:getlastmodified>
<D:resourcetype><D:collection/></D:resourcetype>
<D:lockdiscovery/>
<D:supportedlock>
</D:supportedlock>
</D:prop>
<D:status>HTTP/1.1 200 OK</D:status>
</D:propstat>
</D:response>
<D:response>
<D:href>/test/dir1/test.txt</D:href>
<D:propstat>
<D:prop>
<D:displayname>test.txt</D:displayname>
<D:getcontentlength>22</D:getcontentlength>
<D:getlastmodified>Mon, 16 Jun 2025 08:41:54 GMT</D:getlastmodified>
<D:resourcetype></D:resourcetype>
<D:lockdiscovery/>
<D:supportedlock>
</D:supportedlock>
</D:prop>
<D:status>HTTP/1.1 200 OK</D:status>
</D:propstat>
</D:response>
</D:multistatus>
```

### Get file checksums
`md5` and `sha256` are extra PROPFIND properties served by our fork of
[nginx-dav-ext-module](https://github.com/yamax2/nginx-dav-ext-module) in the
`urn:dav-ext` namespace. They are enabled by `dav_ext_checksums on`
in `config/default.conf`.

They cost a full read of the file, so they are not part of the default response
above: a client has to ask for them by name in the request body. Requesting
`sha256` alone does not also compute `md5`.

Property names are matched without checking the namespace they are declared in,
so any element named `md5` or `sha256` in the request triggers the read.

```sh
curl -k -X PROPFIND -H 'Depth: 0' 'https://node1.application.localhost/service/dir1/test.txt' \
  -H "X-Session-Token: $TOKEN" \
  --data-binary '<?xml version="1.0"?>
<D:propfind xmlns:D="DAV:" xmlns:C="urn:dav-ext">
  <D:prop>
    <C:md5/>
    <C:sha256/>
  </D:prop>
</D:propfind>'
```
response, for a `test.txt` holding `hello checksum world`:
```xml
<?xml version="1.0" encoding="utf-8" ?>
<D:multistatus xmlns:D="DAV:" xmlns:C="urn:dav-ext">
<D:response>
<D:href>/test/dir1/test.txt</D:href>
<D:propstat>
<D:prop>
<C:md5>81f90f926b3e019b743181fd8cdff9bb</C:md5>
<C:sha256>54b546dd1abc7108f73affc828b0771155ac437c380a245f1f183ca4d455c5fc</C:sha256>
</D:prop>
<D:status>HTTP/1.1 200 OK</D:status>
</D:propstat>
</D:response>
</D:multistatus>
```

The same body works with `Depth: 1` to checksum every file in a directory. Note
that this reads every file in it on every request — there is no cache.

The checksum elements are left out of the `200 OK` block, rather than failing
the request, when the entry is not a regular file (directories, FIFOs and
devices are never opened), when it is larger than `dav_ext_checksum_max_size`
(unset by default, meaning no limit), or when it cannot be read.

# Data endpoint

## The domain assumption
Every node is served under the application's own host: the app at, say,
`photos.example.com`, its nodes at `node1.photos.example.com`,
`node2.photos.example.com` and so on. The app sets one cookie, `datasession`,
with `Domain=photos.example.com`, so the browser sends it to every node and no
node has to issue a cookie of its own. A node outside the app's domain never
receives the cookie, and every read from it is a 401.

The app and its nodes are then also same-site, so the cookie is a first-party
one: `SameSite=Lax` carries it on an `<img>`, a `<video>` or a credentialed
`fetch`, and browsers that block third-party cookies do not block it.
`options.conf` holds the CORS headers that let the app's origin read a
`fetch`ed response.

## Authorization
`/data/` takes its token from the `datasession` cookie and checks it against
the same JWKS as `/service/`. The cookie is an RS256 JWT carrying:

| Claim | Description | Example |
|-------|-------------|---------|
| `scope` | Always `"data"` | `"data"` |
| `exp` | Expiration timestamp (Unix) | `1735084800` |

`/data/` requires `scope` to be `"data"`. Service tokens are signed with the
same keys, so without that an upload or download link handed to a client would
also be a read pass to every node. The other direction needs nothing: the
cookie carries no `method`, `uri` or `host`, so `/service/` refuses it.

```sh
curl 'https://node1.photos.example.com/data/dir1/test.txt' \
  -b "datasession=$DATA_TOKEN"
```

Every `/data/` read looks the keys up through `/service_public_key`, an
internal subrequest answered from `proxy_cache`. Its cache settings are
therefore on the path of every image:

- The app's `Cache-Control: max-age` keeps it to one JWKS fetch per ten minutes
  (`proxy_cache_valid` being the fallback for an app that sends none), and
  `proxy_cache_lock` collapses a cold-cache burst into one fetch.
- `proxy_cache_use_stale` keeps reads going while the app is down, which only
  works because `proxy_cache_path` keeps an unread entry for a month
  (`inactive=30d`) instead of nginx's ten minutes.
- The subrequest passes none of the client's headers, nor an upload's body, on
  to the app. Above all not its `Accept-Encoding`: auth_jwt refuses a compressed
  key response, and an app that gzips JSON would do so once the key set grows.
- The fetch verifies the app's certificate (`proxy_ssl_verify`): the key set
  decides every token and every data cookie on the node.

It also means a new key reaches a node up to that `max-age` after the app
publishes it, so the app must publish a key for longer than that before it signs
with it.

# Setup

## TLS certificate
```bash
./gen_keys_example.sh
```
writes a self-signed `keys/server.key` and `keys/server.crt` for the names in
`keys/openssl.cnf`. That certificate is the only key a node holds.

## Docker
`config/default.conf` is a node-only template. Set in it:

- `server_name`: a name under the app's host, the one the app knows the node by
  (its first name is what the tokens' `host` claim must equal);
- in `location = /service_public_key`, `$pubkey_host` (the app's host) and a
  `resolver` that can find it;
- the CA the app's certificate is checked against
  (`proxy_ssl_trusted_certificate`): the system bundle as shipped, or the app's
  own certificate, mounted, for an app on a self-signed one.

Set the app's origin in `config/options.conf`. Then:

```bash
docker network create storagenode
docker run -d -p 443:443 --network storagenode \
  -v "$PWD/keys:/etc/nginx/keys:ro" \
  -v "$PWD/config/default.conf:/etc/nginx/http.d/default.conf:ro" \
  -v "$PWD/config/options.conf:/etc/nginx/options.conf:ro" \
  -v storagenode-files:/data/files \
  yamax2/storagenode
```

The network is what gives the container Docker's embedded DNS at `127.0.0.11`,
the template's `resolver`; on the default bridge network there is none, and every
key fetch, so every request, would fail.

**Upgrading a `default.conf` of your own** from an image with the session
module: remove `location /service/start`; in `/data/`, read
`$cookie_datasession` instead of `$cookie_storagesession`, replace
`auth_jwt_key_file` with `auth_jwt_key_request /service_public_key jwks;` and
require `scope`; in `/service/`, require `host` against `$server_name`; point
`/service_public_key` at the app's `/.well-known/jwks.json` with the cache and
proxy settings above. The template has all of it.

[photostorage2](https://github.com/yamax2/photostorage2)'s dev environment runs
this image with its own configuration and is the test bed for the node.

## Standalone armv7 archive

Releases also carry `storagenode-<version>-linux-armv7.tar.gz` for hosts where
Docker is not an option. It unpacks into a single directory holding the nginx
binary, the two dynamic modules, every shared library they need (the musl
loader included, so it runs on glibc systems too) and an example configuration:

```bash
tar -xzf storagenode-<version>-linux-armv7.tar.gz
cd storagenode-<version>-linux-armv7

# conf/storagenode.conf: server_name, the TLS certificate, the app's host
./run.sh -t
./run.sh -g 'daemon off;'
```

Nothing is installed system-wide and the directory can be moved anywhere; see
`README.md` inside the archive for the expected layout and a systemd unit.
Build it locally with:

```bash
docker buildx build --platform linux/arm/v7 -f bundle/Dockerfile \
  --target bundle -o type=local,dest=./bundle-out .
```
