```nginx
location / {
  auth_jwt "private" token=$arg_token;
  auth_jwt_key_file http.d/key.json;
  auth_jwt_require_header alg eq RS256;
  auth_jwt_phase preaccess;

  auth_jwt_require_claim request_method eq json="$request_method";
  auth_jwt_require_claim uri eq json="$uri";

  proxy_set_header user $jwt_claims;
  proxy_pass https://tretyakov-ma.ru;
}
```
