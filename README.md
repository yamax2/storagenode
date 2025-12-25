# About
Simple nginx webdav node with JWT auth, based on:
* https://github.com/kjdev/nginx-auth-jwt
* https://github.com/arut/nginx-dav-ext-module

# Basic configuration
```nginx
proxy_cache_path /data/nginx/cache levels=1 keys_zone=keys:10m;

location / {
  auth_jwt "private" token=$arg_token;

  # auth_jwt_key_file http.d/key.json;
  auth_jwt_key_request /public_key jwks;

  auth_jwt_require_header alg eq RS256;
  auth_jwt_phase preaccess;

  auth_jwt_require_claim method eq json="$request_method";
  auth_jwt_require_claim uri eq json="$uri";

  root /data;
  dav_methods PUT DELETE MKCOL COPY MOVE;
  dav_ext_methods PROPFIND OPTIONS;
}

location = /public_key {
  internal;
  proxy_cache keys;
  proxy_pass https://audit.api.wallarm.com/v3/edge/portals/public_key;
}
```
## Create JWT token
```ruby
jwk = App.config.dig(:secure_edge, :telemetry_portals, :jwk)
payload = {'method' => 'DELETE', 'uri' => '/test/dir1/', 'exp' => Time.now.to_i + 60}
puts JWT.encode(payload, jwk.signing_key, jwk[:alg], kid: jwk[:kid])
```

# Operations
## Create a dir
```sh
curl -X MKCOL 'http://localhost:8080/test/dir1/?token=...
```
(not recursively)

## Delete a file/dir
```sh
curl -X DELETE 'http://localhost:8080/test/dir1/?token=...
(with backshash at the end for directories)
```
## Put a file
```sh
curl -X PUT 'http://localhost:8080/test/dir1/test.txt?token=...' -T ./test.txt
```
## Get file props
```sh
curl -X PROPFIND 'http://localhost:8080/test/dir1/test.txt?token=...'
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
## List files
```sh
curl -X PROPFIND -H 'Depth: 1' 'http://localhost:8080/test/dir1?token=...'
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
