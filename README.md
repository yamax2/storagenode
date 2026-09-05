# About
Containerized Nginx-based WebDAV file server with dual-layer JWT authentication.

| `/service/*` | `/data/*` |
|--------------|-----------|
| File operations (PUT/DELETE/MKCOL) | Read-only access (GET/HEAD) |
| External JWT auth (`X-Session-Token` header) | Session cookie auth |
| `/service/start` issues 24h session cookie | Uses session cookie |

Based on:
* [nginx-auth-jwt](https://github.com/kjdev/nginx-auth-jwt) - JWT validation
* [nginx-dav-ext-module](https://github.com/yamax2/nginx-dav-ext-module) - WebDAV protocol, forked to add `md5`/`sha256` PROPFIND properties
* `ngx_http_storage_node_session_start_module` - custom module for RS256 session cookies

# Service endpoint

## Authentication
The `/service/` endpoint requires a JWT token in the `X-Session-Token` header. The token must be RS256-signed and contain:

| Claim | Description | Example |
|-------|-------------|---------|
| `method` | HTTP method being performed | `"PUT"`, `"DELETE"`, `"MKCOL"` |
| `uri` | Full request URI | `"/service/dir1/file.txt"` |
| `exp` | Expiration timestamp (Unix) | `1735084800` |

## Generate JWT (Ruby)
```ruby
require 'jwt'
require 'json'

jwk_data = JSON.parse(File.read('keys/node.jwks'))
jwk = JWT::JWK.new(jwk_data['keys'].first)

payload = {
  'method' => 'PUT',
  'uri' => '/service/myfile.txt',
  'exp' => Time.now.to_i + 60
}

token = JWT.encode(payload, jwk.signing_key, 'RS256', kid: jwk[:kid])
```

Using JWK from config (some of my apps):
```ruby
jwk = App.config.dig(:secure_edge, :telemetry_portals, :jwk)
payload = {'method' => 'DELETE', 'uri' => '/service/dir1/', 'exp' => Time.now.to_i + 60}
puts JWT.encode(payload, jwk.signing_key, jwk[:alg], kid: jwk[:kid])
```

## Operations

### Create a directory
```sh
curl -X MKCOL 'http://localhost:8080/service/dir1/' \
  -H "X-Session-Token: $TOKEN"
```
Note: not recursive, parent must exist

### Delete a file/dir
```sh
curl -X DELETE 'http://localhost:8080/service/dir1/' \
  -H "X-Session-Token: $TOKEN"
```
Note: use trailing slash for directories

### Upload a file
```sh
curl -X PUT 'http://localhost:8080/service/dir1/test.txt' \
  -H "X-Session-Token: $TOKEN" \
  -T ./test.txt
```

### Get file properties
```sh
curl -X PROPFIND 'http://localhost:8080/service/dir1/test.txt' \
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
curl -X PROPFIND -H 'Depth: 1' 'http://localhost:8080/service/dir1/' \
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
curl -X PROPFIND -H 'Depth: 0' 'http://localhost:8080/service/dir1/test.txt' \
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

### Start a session
Issues a 24-hour session cookie for `/data/` access:
```sh
curl -X GET 'http://localhost:8080/service/start' \
  -H "X-Session-Token: $TOKEN" \
  -c cookies.txt
```
The response sets `storagesession` cookie signed with the node's private key.

# Data endpoint

Read-only access using session cookie (no per-request JWT needed):

```sh
# Using cookie from /service/start
curl 'http://localhost:8080/data/dir1/test.txt' -b cookies.txt

# Or in browser after session start - cookie is HttpOnly
```

# Setup

## Generate keys and start demo
```bash
./gen_keys_example.sh
docker-compose up -d
```

and open https://application.localhost:8443 in browser
