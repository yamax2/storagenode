#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>

typedef struct {
    ngx_uint_t   ttl;
    ngx_str_t    key_path;
    EVP_PKEY    *pkey;
} ngx_http_storage_node_session_loc_conf_t;

static ngx_int_t ngx_http_storage_node_session_handler(ngx_http_request_t *r);
static char *ngx_http_storage_node_session(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void *ngx_http_storage_node_session_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_storage_node_session_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

static ngx_command_t ngx_http_storage_node_session_commands[] = {
    {
        ngx_string("storage_node_session_start"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE2,
        ngx_http_storage_node_session,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
    },
    ngx_null_command
};

static ngx_http_module_t ngx_http_storage_node_session_module_ctx = {
    NULL,                                          /* preconfiguration */
    NULL,                                          /* postconfiguration */
    NULL,                                          /* create main configuration */
    NULL,                                          /* init main configuration */
    NULL,                                          /* create server configuration */
    NULL,                                          /* merge server configuration */
    ngx_http_storage_node_session_create_loc_conf, /* create location configuration */
    ngx_http_storage_node_session_merge_loc_conf   /* merge location configuration */
};

ngx_module_t ngx_http_storage_node_session_start_module = {
    NGX_MODULE_V1,
    &ngx_http_storage_node_session_module_ctx,
    ngx_http_storage_node_session_commands,
    NGX_HTTP_MODULE,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NGX_MODULE_V1_PADDING
};

static const u_char base64url_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static ngx_int_t
ngx_http_storage_node_session_base64url_encode(ngx_pool_t *pool, u_char *src,
    size_t src_len, ngx_str_t *dst)
{
    size_t  len;
    u_char *d, *s;

    len = (src_len + 2) / 3 * 4;
    dst->data = ngx_pnalloc(pool, len + 1);
    if (dst->data == NULL) {
        return NGX_ERROR;
    }

    s = src;
    d = dst->data;

    while (src_len > 2) {
        *d++ = base64url_table[(s[0] >> 2) & 0x3f];
        *d++ = base64url_table[((s[0] & 0x03) << 4) | ((s[1] >> 4) & 0x0f)];
        *d++ = base64url_table[((s[1] & 0x0f) << 2) | ((s[2] >> 6) & 0x03)];
        *d++ = base64url_table[s[2] & 0x3f];
        s += 3;
        src_len -= 3;
    }

    if (src_len > 0) {
        *d++ = base64url_table[(s[0] >> 2) & 0x3f];
        if (src_len == 1) {
            *d++ = base64url_table[(s[0] & 0x03) << 4];
        } else {
            *d++ = base64url_table[((s[0] & 0x03) << 4) | ((s[1] >> 4) & 0x0f)];
            *d++ = base64url_table[(s[1] & 0x0f) << 2];
        }
    }

    dst->len = d - dst->data;
    *d = '\0';

    return NGX_OK;
}

static ngx_int_t
ngx_http_storage_node_session_load_key(ngx_http_request_t *r,
    ngx_http_storage_node_session_loc_conf_t *conf)
{
    FILE     *fp;
    char      path[NGX_MAX_PATH];

    if (conf->pkey != NULL) {
        return NGX_OK;
    }

    if (conf->key_path.len >= NGX_MAX_PATH) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "storage_node_session: key path too long");
        return NGX_ERROR;
    }

    ngx_memcpy(path, conf->key_path.data, conf->key_path.len);
    path[conf->key_path.len] = '\0';

    fp = fopen(path, "r");
    if (fp == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                      "storage_node_session: failed to open key file \"%s\"", path);
        return NGX_ERROR;
    }

    conf->pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);

    if (conf->pkey == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "storage_node_session: failed to read private key from \"%s\"", path);
        return NGX_ERROR;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_storage_node_session_sign(ngx_http_request_t *r, EVP_PKEY *pkey,
    u_char *data, size_t data_len, ngx_str_t *sig)
{
    EVP_MD_CTX   *mdctx;
    size_t        sig_len;
    u_char       *sig_buf;

    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        return NGX_ERROR;
    }

    if (EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pkey) != 1) {
        EVP_MD_CTX_free(mdctx);
        return NGX_ERROR;
    }

    if (EVP_DigestSignUpdate(mdctx, data, data_len) != 1) {
        EVP_MD_CTX_free(mdctx);
        return NGX_ERROR;
    }

    if (EVP_DigestSignFinal(mdctx, NULL, &sig_len) != 1) {
        EVP_MD_CTX_free(mdctx);
        return NGX_ERROR;
    }

    sig_buf = ngx_pnalloc(r->pool, sig_len);
    if (sig_buf == NULL) {
        EVP_MD_CTX_free(mdctx);
        return NGX_ERROR;
    }

    if (EVP_DigestSignFinal(mdctx, sig_buf, &sig_len) != 1) {
        EVP_MD_CTX_free(mdctx);
        return NGX_ERROR;
    }

    EVP_MD_CTX_free(mdctx);

    sig->data = sig_buf;
    sig->len = sig_len;

    return NGX_OK;
}

static ngx_int_t
ngx_http_storage_node_session_handler(ngx_http_request_t *r)
{
    ngx_http_storage_node_session_loc_conf_t  *conf;
    ngx_str_t     header_b64, payload_b64, sig_b64, sig_raw;
    ngx_str_t     token;
    ngx_table_elt_t  *set_cookie;
    ngx_buf_t    *b;
    ngx_chain_t   out;
    u_char       *signing_input;
    size_t        signing_input_len;
    time_t        exp;
    u_char        header[] = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";
    u_char        payload[64];
    size_t        payload_len;

    if (!(r->method & NGX_HTTP_GET)) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_http_storage_node_session_start_module);

    if (conf->ttl == 0 || conf->key_path.len == 0) {
        return NGX_DECLINED;
    }

    if (ngx_http_storage_node_session_load_key(r, conf) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Encode header */
    if (ngx_http_storage_node_session_base64url_encode(r->pool, header,
            sizeof(header) - 1, &header_b64) != NGX_OK)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Build payload */
    exp = ngx_time() + conf->ttl;
    payload_len = ngx_snprintf(payload, sizeof(payload), "{\"exp\":%T}", exp) - payload;

    if (ngx_http_storage_node_session_base64url_encode(r->pool, payload,
            payload_len, &payload_b64) != NGX_OK)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Build signing input: header.payload */
    signing_input_len = header_b64.len + 1 + payload_b64.len;
    signing_input = ngx_pnalloc(r->pool, signing_input_len);
    if (signing_input == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_memcpy(signing_input, header_b64.data, header_b64.len);
    signing_input[header_b64.len] = '.';
    ngx_memcpy(signing_input + header_b64.len + 1, payload_b64.data, payload_b64.len);

    /* Sign */
    if (ngx_http_storage_node_session_sign(r, conf->pkey, signing_input,
            signing_input_len, &sig_raw) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "storage_node_session: failed to sign JWT");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Encode signature */
    if (ngx_http_storage_node_session_base64url_encode(r->pool, sig_raw.data,
            sig_raw.len, &sig_b64) != NGX_OK)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Build full token */
    token.len = signing_input_len + 1 + sig_b64.len;
    token.data = ngx_pnalloc(r->pool, token.len);
    if (token.data == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_memcpy(token.data, signing_input, signing_input_len);
    token.data[signing_input_len] = '.';
    ngx_memcpy(token.data + signing_input_len + 1, sig_b64.data, sig_b64.len);

    /* Set cookie header */
    set_cookie = ngx_list_push(&r->headers_out.headers);
    if (set_cookie == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    set_cookie->hash = 1;
    ngx_str_set(&set_cookie->key, "Set-Cookie");
    set_cookie->value.len = sizeof("storagesession=; Path=/; HttpOnly") - 1 + token.len;
    set_cookie->value.data = ngx_pnalloc(r->pool, set_cookie->value.len);
    if (set_cookie->value.data == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_snprintf(set_cookie->value.data, set_cookie->value.len + 1,
                 "storagesession=%V; Path=/; HttpOnly", &token);

    /* Send response */
    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = 0;

    ngx_http_send_header(r);

    if (r->header_only) {
        return NGX_OK;
    }

    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->last_buf = 1;
    b->last_in_chain = 1;

    out.buf = b;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}

static void *
ngx_http_storage_node_session_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_storage_node_session_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_storage_node_session_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->ttl = NGX_CONF_UNSET_UINT;
    conf->pkey = NULL;

    return conf;
}

static char *
ngx_http_storage_node_session_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_storage_node_session_loc_conf_t *prev = parent;
    ngx_http_storage_node_session_loc_conf_t *conf = child;

    ngx_conf_merge_uint_value(conf->ttl, prev->ttl, 0);
    ngx_conf_merge_str_value(conf->key_path, prev->key_path, "");

    if (conf->pkey == NULL) {
        conf->pkey = prev->pkey;
    }

    return NGX_CONF_OK;
}

static char *
ngx_http_storage_node_session(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_storage_node_session_loc_conf_t *lcf = conf;
    ngx_str_t        *value;
    ngx_http_core_loc_conf_t  *clcf;

    value = cf->args->elts;

    lcf->ttl = ngx_atoi(value[1].data, value[1].len);
    if (lcf->ttl == (ngx_uint_t) NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid ttl value \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    lcf->key_path = value[2];

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_storage_node_session_handler;

    return NGX_CONF_OK;
}
