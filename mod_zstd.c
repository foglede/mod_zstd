/* 
* 我查看RFC规则的时候，我暂时没有ZSTD到底能不能在HTTP1下开启
* 大部分现代浏览器在HTTP1下都不发送ZSTD 头，这在一定程度上影响了我对该模块的测试
* 2025年2月8日
* https://github.com/foglede/mod_zstd
*/

#include "httpd.h"
#include "http_core.h"
#include "http_log.h"
#include "apr_strings.h"
#include "http_protocol.h"
#include "http_config.h"

#include <zstd.h>


module AP_MODULE_DECLARE_DATA zstd_module;

typedef enum {
    ETAG_MODE_ADDSUFFIX = 0,
    ETAG_MODE_NOCHANGE = 1,
    ETAG_MODE_REMOVE = 2
} etag_mode_e;

typedef struct zstd_server_config_t {
    int compression_level;
    int window_size;
    int strategy;
    etag_mode_e etag_mode;
    const char *note_ratio_name;
    const char *note_input_name;
    const char *note_output_name;
} zstd_server_config_t;

static void *create_server_config(apr_pool_t *p, server_rec *s)
{
    zstd_server_config_t *conf = apr_pcalloc(p, sizeof(*conf));

    /* 后续再改成从配置中读取 */
    conf->compression_level = 7;  // 默认压缩级别，类似于 brotli 的 quality=5
    conf->window_size = 128;
    // https://raw.githack.com/facebook/zstd/release/doc/zstd_manual.html#Chapter2 
    conf->strategy = ZSTD_fast;
    conf->etag_mode = ETAG_MODE_ADDSUFFIX;

    return conf;
}

static const char *set_filter_note(cmd_parms *cmd, void *dummy,
                                   const char *arg1, const char *arg2)
{
    zstd_server_config_t *conf =
        ap_get_module_config(cmd->server->module_config, &zstd_module);

    if (!arg2) {
        conf->note_ratio_name = arg1;
        return NULL;
    }

    if (ap_cstr_casecmp(arg1, "Ratio") == 0) {
        conf->note_ratio_name = arg2;
    }
    else if (ap_cstr_casecmp(arg1, "Input") == 0) {
        conf->note_input_name = arg2;
    }
    else if (ap_cstr_casecmp(arg1, "Output") == 0) {
        conf->note_output_name = arg2;
    }
    else {
        return apr_psprintf(cmd->pool, "Unknown ZstdFilterNote type '%s'",
                            arg1);
    }

    return NULL;
}

static const char *set_compression_level(cmd_parms *cmd, void *dummy,
                                         const char *arg)
{
    zstd_server_config_t *conf =
        ap_get_module_config(cmd->server->module_config, &zstd_module);
    int val = atoi(arg);

    if (val < ZSTD_minCLevel() || val > ZSTD_maxCLevel()) {
        return apr_psprintf(cmd->pool, "ZstdCompressionLevel must be between %d and %d",
                            ZSTD_minCLevel(), ZSTD_maxCLevel());
    }

    conf->compression_level = val;
    return NULL;
}

static const char *set_window_size(cmd_parms *cmd, void *dummy,
                                   const char *arg)
{
    zstd_server_config_t *conf =
        ap_get_module_config(cmd->server->module_config, &zstd_module);
    int val = atoi(arg);

    if (val < 0 || val > 128) {
        return apr_psprintf(cmd->pool, "ZstdWindowSize must be between %d and %d",
                            0, 128);
    }


    conf->window_size = val;
    return NULL;
}

static const char *set_etag_mode(cmd_parms *cmd, void *dummy,
                                 const char *arg)
{
    zstd_server_config_t *conf =
        ap_get_module_config(cmd->server->module_config, &zstd_module);

    if (ap_cstr_casecmp(arg, "AddSuffix") == 0) {
        conf->etag_mode = ETAG_MODE_ADDSUFFIX;
    }
    else if (ap_cstr_casecmp(arg, "NoChange") == 0) {
        conf->etag_mode = ETAG_MODE_NOCHANGE;
    }
    else if (ap_cstr_casecmp(arg, "Remove") == 0) {
        conf->etag_mode = ETAG_MODE_REMOVE;
    }
    else {
        return "ZstdAlterETag accepts only 'AddSuffix', 'NoChange' and 'Remove'";
    }

    return NULL;
}

typedef struct zstd_ctx_t {
    ZSTD_CCtx *cctx;
    apr_bucket_brigade *bb;
    apr_off_t total_in;
    apr_off_t total_out;
} zstd_ctx_t;

static apr_status_t cleanup_ctx(void *data)
{
    zstd_ctx_t *ctx = data;

    ZSTD_freeCCtx(ctx->cctx);
    ctx->cctx = NULL;
    return APR_SUCCESS;
}

static zstd_ctx_t *create_ctx(int compression_level,
                              int window_size,
                              apr_bucket_alloc_t *alloc,
                              apr_pool_t *pool)
{
    zstd_ctx_t *ctx = apr_pcalloc(pool, sizeof(*ctx));

    ctx->cctx = ZSTD_createCCtx();
    ZSTD_CCtx_setParameter(ctx->cctx, ZSTD_c_compressionLevel, compression_level);
    ZSTD_CCtx_setParameter(ctx->cctx, ZSTD_c_windowLog, window_size);
    apr_pool_cleanup_register(pool, ctx, cleanup_ctx, apr_pool_cleanup_null);

    ctx->bb = apr_brigade_create(pool, alloc);
    ctx->total_in = 0;
    ctx->total_out = 0;

    return ctx;
}

static apr_status_t process_chunk(zstd_ctx_t *ctx,
                                  const void *data,
                                  apr_size_t len,
                                  ap_filter_t *f)
{
    ZSTD_inBuffer input = { data, len, 0 };
    size_t out_size = ZSTD_compressBound(len);
    char *out_buffer = apr_palloc(f->r->pool, out_size);
    ZSTD_outBuffer output = { out_buffer, out_size, 0 };

    size_t remaining = ZSTD_compressStream2(ctx->cctx, &output, &input, ZSTD_e_continue);
    if (ZSTD_isError(remaining)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, f->r, APLOGNO(03459)
                      "Error while compressing data: %s",
                      ZSTD_getErrorName(remaining));
        return APR_EGENERAL;
    }

    if (output.pos > 0) {
        apr_bucket *b = apr_bucket_heap_create(out_buffer, output.pos, NULL,
                                              ctx->bb->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(ctx->bb, b);
        
        apr_status_t rv = ap_pass_brigade(f->next, ctx->bb);
        apr_brigade_cleanup(ctx->bb);
        if (rv != APR_SUCCESS) {
            return rv;
        }
    }

    ctx->total_in += len;
    ctx->total_out += output.pos;
    return APR_SUCCESS;
}

static apr_status_t flush(zstd_ctx_t *ctx,
                          ZSTD_EndDirective mode,
                          ap_filter_t *f)
{
    ZSTD_inBuffer input = { NULL, 0, 0 };
    size_t out_size = ZSTD_compressBound(ZSTD_CStreamInSize());
    char *out_buffer = apr_palloc(f->r->pool, out_size);
    ZSTD_outBuffer output = { out_buffer, out_size, 0 };

    size_t remaining;
    do {
        remaining = ZSTD_compressStream2(ctx->cctx, &output, &input, mode);
        if (ZSTD_isError(remaining)) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, f->r, APLOGNO(03460)
                          "Error while flushing data: %s",
                          ZSTD_getErrorName(remaining));
            return APR_EGENERAL;
        }

        if (output.pos > 0) {
            apr_bucket *b = apr_bucket_heap_create(out_buffer, output.pos, NULL,
                                                  ctx->bb->bucket_alloc);
            APR_BRIGADE_INSERT_TAIL(ctx->bb, b);
            ctx->total_out += output.pos;
        }
    } while (remaining > 0);

    return APR_SUCCESS;
}

static const char *get_content_encoding(request_rec *r)
{
    const char *encoding;

    encoding = apr_table_get(r->headers_out, "Content-Encoding");
    if (encoding) {
        const char *err_enc;

        err_enc = apr_table_get(r->err_headers_out, "Content-Encoding");
        if (err_enc) {
            encoding = apr_pstrcat(r->pool, encoding, ",", err_enc, NULL);
        }
    }
    else {
        encoding = apr_table_get(r->err_headers_out, "Content-Encoding");
    }

    if (r->content_encoding) {
        encoding = encoding ? apr_pstrcat(r->pool, encoding, ",",
                                          r->content_encoding, NULL)
                            : r->content_encoding;
    }

    return encoding;
}

static apr_status_t compress_filter(ap_filter_t *f, apr_bucket_brigade *bb)
{
    request_rec *r = f->r;
    zstd_ctx_t *ctx = f->ctx;
    apr_status_t rv;
    zstd_server_config_t *conf;

    if (APR_BRIGADE_EMPTY(bb)) {
        return APR_SUCCESS;
    }

    conf = ap_get_module_config(r->server->module_config, &zstd_module);

    if (!ctx) {
        const char *encoding;
        const char *token;
        const char *accepts;
        const char *q = NULL;

        if (r->main || r->status == HTTP_NO_CONTENT
            || apr_table_get(r->subprocess_env, "no-zstd")
            || apr_table_get(r->headers_out, "Content-Range")) {
            ap_remove_output_filter(f);
            return ap_pass_brigade(f->next, bb);
        }

        encoding = get_content_encoding(r);

        if (encoding) {
            const char *tmp = encoding;

            token = ap_get_token(r->pool, &tmp, 0);
            // 我认为没必要这个循环 ，AI也没理解这个while 在干啥？安全检查吗？
            while (token && *token) {
                if (strcmp(token, "identity") != 0 &&
                    strcmp(token, "7bit") != 0 &&
                    strcmp(token, "8bit") != 0 &&
                    strcmp(token, "binary") != 0) {
                    ap_remove_output_filter(f);
                    return ap_pass_brigade(f->next, bb);
                }

                if (*tmp) {
                    ++tmp;
                }
                token = (*tmp) ? ap_get_token(r->pool, &tmp, 0) : NULL;
            }
        }

        apr_table_mergen(r->headers_out, "Vary", "Accept-Encoding");

        accepts = apr_table_get(r->headers_in, "Accept-Encoding");
        if (!accepts) {
            ap_remove_output_filter(f);
            return ap_pass_brigade(f->next, bb);
        }

        token = ap_get_token(r->pool, &accepts, 0);
        while (token && token[0] && ap_cstr_casecmp(token, "zstd") != 0) {
            while (*accepts == ';') {
                ++accepts;
                ap_get_token(r->pool, &accepts, 1);
            }

            if (*accepts == ',') {
                ++accepts;
            }
            token = (*accepts) ? ap_get_token(r->pool, &accepts, 0) : NULL;
        }

        if (*accepts) {
            while (*accepts == ';') {
                ++accepts;
            }
            q = ap_get_token(r->pool, &accepts, 1);
        }

        if (!token || token[0] == '\0' ||
            (q && strlen(q) >= 3 && strncmp("q=0.000", q, strlen(q)) == 0)) {
            ap_remove_output_filter(f);
            return ap_pass_brigade(f->next, bb);
        }

        if (!encoding || ap_cstr_casecmp(encoding, "identity") == 0) {
            apr_table_setn(r->headers_out, "Content-Encoding", "zstd");
        } else {
            apr_table_mergen(r->headers_out, "Content-Encoding", "zstd");
        }

        if (r->content_encoding) {
            r->content_encoding = apr_table_get(r->headers_out,
                                                "Content-Encoding");
        }

        apr_table_unset(r->headers_out, "Content-Length");
        apr_table_unset(r->headers_out, "Content-MD5");

        if (conf->etag_mode == ETAG_MODE_REMOVE) {
            apr_table_unset(r->headers_out, "ETag");
        }
        else if (conf->etag_mode == ETAG_MODE_ADDSUFFIX) {
            const char *etag = apr_table_get(r->headers_out, "ETag");

            if (etag) {
                apr_size_t len = strlen(etag);

                if (len > 2 && etag[len - 1] == '"') {
                    etag = apr_pstrmemdup(r->pool, etag, len - 1);
                    etag = apr_pstrcat(r->pool, etag, "-zstd\"", NULL);
                    apr_table_setn(r->headers_out, "ETag", etag);
                }
            }
        }

        if (r->status == HTTP_NOT_MODIFIED) {
            ap_remove_output_filter(f);
            return ap_pass_brigade(f->next, bb);
        }

        ctx = create_ctx(conf->compression_level, conf->window_size,
                         f->c->bucket_alloc, r->pool);
        f->ctx = ctx;
    }

    while (!APR_BRIGADE_EMPTY(bb)) {
        apr_bucket *e = APR_BRIGADE_FIRST(bb);

        if (r->header_only && r->bytes_sent) {
            ap_remove_output_filter(f);
            return ap_pass_brigade(f->next, bb);
        }

        if (APR_BUCKET_IS_EOS(e)) {
            rv = flush(ctx, ZSTD_e_end, f);
            if (rv != APR_SUCCESS) {
                return rv;
            }

            if (conf->note_input_name) {
                apr_table_setn(r->notes, conf->note_input_name,
                               apr_off_t_toa(r->pool, ctx->total_in));
            }
            if (conf->note_output_name) {
                apr_table_setn(r->notes, conf->note_output_name,
                               apr_off_t_toa(r->pool, ctx->total_out));
            }
            if (conf->note_ratio_name) {
                if (ctx->total_in > 0) {
                    int ratio = (int) (ctx->total_out * 100 / ctx->total_in);
                    apr_table_setn(r->notes, conf->note_ratio_name,
                                   apr_itoa(r->pool, ratio));
                }
                else {
                    apr_table_setn(r->notes, conf->note_ratio_name, "-");
                }
            }

            APR_BUCKET_REMOVE(e);
            APR_BRIGADE_INSERT_TAIL(ctx->bb, e);

            rv = ap_pass_brigade(f->next, ctx->bb);
            apr_brigade_cleanup(ctx->bb);
            apr_pool_cleanup_run(r->pool, ctx, cleanup_ctx);
            return rv;
        }
        else if (APR_BUCKET_IS_FLUSH(e)) {
            rv = flush(ctx, ZSTD_e_flush, f);
            if (rv != APR_SUCCESS) {
                return rv;
            }

            APR_BUCKET_REMOVE(e);
            APR_BRIGADE_INSERT_TAIL(ctx->bb, e);

            rv = ap_pass_brigade(f->next, ctx->bb);
            apr_brigade_cleanup(ctx->bb);
            if (rv != APR_SUCCESS) {
                return rv;
            }
        }
        else if (APR_BUCKET_IS_METADATA(e)) {
            APR_BUCKET_REMOVE(e);
            APR_BRIGADE_INSERT_TAIL(ctx->bb, e);
        }
        else {
            const char *data;
            apr_size_t len;

            rv = apr_bucket_read(e, &data, &len, APR_BLOCK_READ);
            if (rv != APR_SUCCESS) {
                return rv;
            }
            rv = process_chunk(ctx, data, len, f);
            if (rv != APR_SUCCESS) {
                return rv;
            }
            apr_bucket_delete(e);
        }
    }
    return APR_SUCCESS;
}

static int zstd_status_handler(request_rec *r)
{
    if (strcmp(r->handler, "zstd-status")) {
        return DECLINED;
    }

    ap_set_content_type(r, "text/html;charset=utf-8");
    ap_rputs("<html><head><title>Zstd Module Status</title></head><body>", r);
    ap_rputs("https://github.com/foglede/mod_zstd", r);


    ap_rputs("</body></html>", r);

    return OK;
}

static int zstd_info_handler(request_rec *r)
{
    if (strcmp(r->handler, "zstd-info")) {
        return DECLINED;
    }

    ap_set_content_type(r, "text/html;charset=utf-8");
    ap_rputs("<html><head><title>Zstd Module Info</title></head><body>", r);
    ap_rputs("<h1>Zstd Compression Module Configuration : https://github.com/foglede/mod_zstd</h1>", r);

    // 使用 ap_rprintf 来格式化输出
    ap_rputs( "<h2>ZSTD lib ver:", r);
    ap_rputs(ZSTD_versionString(), r);
    ap_rputs("</h2>", r);


    ap_rputs("</body></html>", r);

    return OK;
}

static void register_hooks(apr_pool_t *p)
{
    ap_hook_handler(zstd_status_handler, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_handler(zstd_info_handler, NULL, NULL, APR_HOOK_MIDDLE);
    ap_register_output_filter("ZSTD_COMPRESS", compress_filter, NULL,
                              AP_FTYPE_CONTENT_SET);
}

static const command_rec zstd_config_cmds[] = {
    AP_INIT_TAKE12("ZstdFilterNote", set_filter_note,
                   NULL, RSRC_CONF,
                   "Set a note to report on compression ratio"),
    AP_INIT_TAKE1("ZstdCompressionLevel", set_compression_level,
                  NULL, RSRC_CONF,
                  "Compression level between min and max (higher level means "
                  "better compression but slower)"),
    AP_INIT_TAKE1("ZstdWindowSize", set_window_size,
                  NULL, RSRC_CONF,
                  "Window size between min and max (larger windows can "
                  "improve compression, but require more memory)"),
    AP_INIT_TAKE1("ZstdAlterETag", set_etag_mode,
                  NULL, RSRC_CONF,
                  "Set how mod_zstd should modify ETag response headers: "
                  "'AddSuffix' (default), 'NoChange', 'Remove'"),
    {NULL}
};

AP_DECLARE_MODULE(zstd) = {
    STANDARD20_MODULE_STUFF,
    NULL,                      /* create per-directory config structure */
    NULL,                      /* merge per-directory config structures */
    create_server_config,      /* create per-server config structure */
    NULL,                      /* merge per-server config structures */
    zstd_config_cmds,          /* command apr_table_t */
    register_hooks             /* register hooks */
}; 
