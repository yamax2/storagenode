# About
Containerized Nginx-based WebDAV file server with dual-layer JWT authentication.

| `/service/*` | `/data/*` |
|--------------|-----------|
| File operations (PUT/DELETE/MKCOL) | Read-only access (GET/HEAD) |
| External JWT auth (`X-Session-Token` header) | Session cookie auth |
| `/service/start` issues 24h session cookie | Uses session cookie |

Based on:
* [nginx-auth-jwt](https://github.com/kjdev/nginx-auth-jwt) - JWT validation
* [nginx-dav-ext-module](https://github.com/arut/nginx-dav-ext-module) - WebDAV protocol
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
