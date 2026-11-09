# Builds a self-contained, relocatable nginx bundle: the binary, its dynamic
# modules and every shared library they need at the top level, the example
# configuration in conf/. Everything is exported through a scratch stage so
# buildx can write it straight to the host with `--output type=local`.
#
# The build context is the repository root, not this directory -- the COPY
# below names bundle/ by its path from there, which is how the release workflow
# builds it too:
#
#   docker buildx build --platform linux/arm/v7 -f bundle/Dockerfile \
#     --target bundle -o type=local,dest=./bundle-out .

FROM alpine AS builder

WORKDIR /build

RUN apk --no-cache upgrade && \
    apk --no-cache add \
      build-base       \
      ca-certificates  \
      curl             \
      git              \
      jansson-dev      \
      libxml2-dev      \
      libxslt-dev      \
      linux-headers    \
      nginx            \
      openssl-dev      \
      pcre2-dev        \
      zlib-dev      && \
    nginx_version=$(nginx -v 2>&1 | sed 's/^[^0-9]*//') && \
    echo "$nginx_version" > /nginx_version && \
    curl -sL -o nginx-${nginx_version}.tar.gz http://nginx.org/download/nginx-${nginx_version}.tar.gz && \
    tar -xf nginx-${nginx_version}.tar.gz && \
    mv nginx-${nginx_version} nginx && \
    git clone --recurse-submodules https://github.com/kjdev/nginx-auth-jwt.git && \
    git clone https://github.com/yamax2/nginx-dav-ext-module.git

# Unlike the Docker image we do not reuse the distro's configure arguments: the
# bundle has to be relocatable, so every path is relative and resolved against
# the runtime prefix passed via `nginx -p`.
RUN cd nginx && \
    ./configure \
      --prefix=/opt/storagenode \
      --sbin-path=nginx \
      --modules-path=. \
      --conf-path=conf/nginx.conf \
      --pid-path=nginx.pid \
      --lock-path=nginx.lock \
      --error-log-path=stderr \
      --http-log-path=access.log \
      --http-client-body-temp-path=tmp/client_body \
      --http-proxy-temp-path=tmp/proxy \
      --http-fastcgi-temp-path=tmp/fastcgi \
      --http-uwsgi-temp-path=tmp/uwsgi \
      --http-scgi-temp-path=tmp/scgi \
      --with-compat \
      --with-threads \
      --with-file-aio \
      --with-pcre-jit \
      --with-http_ssl_module \
      --with-http_v2_module \
      --with-http_dav_module \
      --with-http_xslt_module \
      --with-http_realip_module \
      --with-http_stub_status_module \
      --with-http_gzip_static_module \
      --add-dynamic-module=../nginx-auth-jwt \
      --add-dynamic-module=../nginx-dav-ext-module \
      --with-cc-opt='-DNGX_HTTP_HEADERS' && \
    make -j"$(nproc)"

COPY bundle /bundle_src

# Assemble the bundle: binary, modules and their shared libraries (including the
# musl loader, so the bundle also runs on glibc-based armv7 systems) at the root,
# where nginx resolves them against the prefix; every configuration file in
# conf/, where nginx resolves includes against the main config file. The node
# holds no key of its own, so nothing ships for it: the TLS certificate is the
# operator's, put in place at deploy time (the example config reaches lego's
# output as `.lego/certificates/...`, relative to conf/). The CA bundle goes to
# conf/ as well: the node verifies the app it fetches its JWKS from, and a NAS
# has no CA path nginx could rely on.
RUN set -eu; \
    mkdir -p /bundle/conf; \
    cp nginx/objs/nginx                                            /bundle/; \
    cp nginx/objs/ngx_http_auth_jwt_module.so                      /bundle/; \
    cp nginx/objs/ngx_http_dav_ext_module.so                       /bundle/; \
    cp nginx/conf/mime.types                                       /bundle/conf/; \
    cp /bundle_src/conf/nginx.conf /bundle_src/conf/storagenode.conf \
       /bundle_src/conf/options.conf                                   /bundle/conf/; \
    cp /etc/ssl/certs/ca-certificates.crt                              /bundle/conf/; \
    cp /bundle_src/README.md /bundle_src/run.sh                        /bundle/; \
    chmod 755 /bundle/run.sh /bundle/nginx; \
    : > /tmp/todo; : > /tmp/seen; \
    for f in /bundle/nginx /bundle/*.so; do echo "$f" >> /tmp/todo; done; \
    while [ -s /tmp/todo ]; do \
      f=$(head -n1 /tmp/todo); sed -i '1d' /tmp/todo; \
      grep -qxF "$f" /tmp/seen && continue; \
      echo "$f" >> /tmp/seen; \
      ldd "$f" 2>/dev/null | grep -o '/[^ ()]*\.so[^ ()]*' | sort -u | while read -r lib; do \
        [ -f "$lib" ] || continue; \
        base=$(basename "$lib"); \
        [ -e "/bundle/$base" ] || cp -L "$lib" "/bundle/$base"; \
        echo "/bundle/$base" >> /tmp/todo; \
      done; \
    done; \
    cp /nginx_version /bundle/VERSION.nginx; \
    strip /bundle/nginx /bundle/*.so; \
    ls -laR /bundle

# Smoke test: load every module through the bundled loader. The example config
# is not used here because it references TLS keys that only exist at deploy time.
RUN set -eu; \
    printf 'load_module ngx_http_auth_jwt_module.so;\nload_module ngx_http_dav_ext_module.so;\nevents {}\nhttp { include mime.types; }\n' > /bundle/conf/smoke.conf; \
    "$(ls /bundle/ld-musl-*.so.1)" --library-path /bundle /bundle/nginx -p /bundle/ -c /bundle/conf/smoke.conf -t; \
    rm -rf /bundle/conf/smoke.conf /bundle/nginx.pid /bundle/tmp; \
    ls -laR /bundle

FROM scratch AS bundle
COPY --from=builder /bundle /
