# About
Simple nginx webdav node with JWT auth, based on:
* https://github.com/kjdev/nginx-auth-jwt
* https://github.com/arut/nginx-dav-ext-module
* custom module for sessions

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

## Key generation and start
```bash
mkdir -p keys
openssl genrsa -out keys/node1.pem 2048
./jwks.sh keys/node.pem > keys/node.jwks
docker run --rm -d -p 8082:80 -v $PWD/keys:/etc/nginx/keys zozo
```
