FROM alpine AS builder

WORKDIR /build

COPY ngx_http_storage_node_session_start_module /build/ngx_http_storage_node_session_start_module

RUN apk --no-cache upgrade && \
    apk --no-cache add \
      build-base       \
      curl             \
      geoip-dev        \
      jansson-dev      \
      libxslt-dev      \
      openssl-dev      \
      pcre-dev         \
      perl-dev         \
      git              \
      nginx            \
      linux-headers    \
      gd-dev           \
      zlib-dev      && \
    nginx_version=$(nginx -v 2>&1 | sed 's/^[^0-9]*//') && \
    curl -sL -o nginx-${nginx_version}.tar.gz http://nginx.org/download/nginx-${nginx_version}.tar.gz && \
    tar -xf nginx-${nginx_version}.tar.gz && \
    mv nginx-${nginx_version} nginx && \
    git clone https://github.com/kjdev/nginx-auth-jwt.git && \
    git clone https://github.com/arut/nginx-dav-ext-module.git

RUN nginx_opt=$(nginx -V 2>&1 | tail -1 | sed -e "s/configure arguments://" -e "s| --add-dynamic-module=[^ ]*||g") && \
    cd nginx                              && \
    ./configure ${nginx_opt}                 \
      --add-dynamic-module=../nginx-auth-jwt \
      --add-dynamic-module=../nginx-dav-ext-module \
      --add-dynamic-module=../ngx_http_storage_node_session_start_module \
      --with-cc-opt='-DNGX_HTTP_HEADERS'  && \
    make                                  && \
    mkdir -p /usr/lib/nginx/modules       && \
    cp objs/ngx_http_auth_jwt_module.so   /usr/lib/nginx/modules/ && \
    cp objs/ngx_http_dav_ext_module.so    /usr/lib/nginx/modules/ && \
    cp objs/ngx_http_storage_node_session_start_module.so /usr/lib/nginx/modules/ && \
    mkdir -p /etc/nginx/modules           && \
    echo 'load_module "/usr/lib/nginx/modules/ngx_http_auth_jwt_module.so";' > /etc/nginx/modules/auth_jwt.conf && \
    echo 'load_module "/usr/lib/nginx/modules/ngx_http_dav_ext_module.so";' > /etc/nginx/modules/dav_ext.conf   && \
    echo 'load_module "/usr/lib/nginx/modules/ngx_http_storage_node_session_start_module.so";' > /etc/nginx/modules/storage_node_session.conf && \
    nginx -t

FROM alpine

RUN apk --no-cache upgrade && \
    apk --no-cache add        \
      jansson                 \
      libxslt                 \
      nginx                && \
    sed \
      -e 's/^user /#user /' \
      -e 's@^error_log .*$@error_log /dev/stderr warn;@' \
      -e 's@access_log .*;$@access_log /dev/stdout main;@' \
      -i /etc/nginx/nginx.conf

COPY --from=builder /usr/lib/nginx/modules/ngx_http_auth_jwt_module.so /usr/lib/nginx/modules/ngx_http_auth_jwt_module.so
COPY --from=builder /usr/lib/nginx/modules/ngx_http_dav_ext_module.so /usr/lib/nginx/modules/ngx_http_dav_ext_module.so
COPY --from=builder /usr/lib/nginx/modules/ngx_http_storage_node_session_start_module.so /usr/lib/nginx/modules/ngx_http_storage_node_session_start_module.so

COPY --from=builder /etc/nginx/modules/auth_jwt.conf /etc/nginx/modules/auth_jwt.conf
COPY --from=builder /etc/nginx/modules/dav_ext.conf /etc/nginx/modules/dav_ext.conf
COPY --from=builder /etc/nginx/modules/storage_node_session.conf /etc/nginx/modules/storage_node_session.conf

USER nginx
CMD ["nginx", "-g", "daemon off;"]
