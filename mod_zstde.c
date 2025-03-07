/*
* 2025-02-08 
* 2025-02-09
* Http1 可以zstd
* @author https://github.com/foglede/mod_zstd
*/
#include "httpd.h"
#include "http_core.h"
#include "http_log.h"
#include "apr_strings.h"
#include "http_protocol.h"
#include "http_config.h"
#include "ap_hooks.h"       
#include "apr_optional.h"    
#include "apr_optional_hooks.h"
#include <apr.h>
#include <apr_general.h>
#include <apr_pools.h>
#include <apr_thread_proc.h>
#include <apr_errno.h>

#include "mod_status.h"

#include <zstd.h>
#include "mod_zstd.h"

#ifdef _WIN32
#include <windows.h>
#elif defined(unix) || defined(__unix__) || defined(__APPLE__)
#include <unistd.h>
#endif

module AP_MODULE_DECLARE_DATA zstd_module;

static void *create_server_config(apr_pool_t *p, server_rec *s) {

    zstd_server_config_t *conf = apr_pcalloc(p, sizeof(*conf));
    conf->compression_level = 17;
    conf->etag_mode = ETAG_MODE_ADDSUFFIX;
    conf->strategy = ZSTD_fast;
    
    return conf;
}

static const char *set_filter_note(cmd_parms *cmd, void *dummy, const char *arg1, const char *arg2) {

    zstd_server_config_t *conf =
        ap_get_module_config(cmd->server->module_config, &zstd_module);

    if (!arg2) {
        conf->note_ratio_name = arg1;
        return NULL;
    }

    if (ap_cstr_casecmp(arg1, "Ratio") == 0) {
        conf->note_ratio_name = arg2;
    } else if (ap_cstr_casecmp(arg1, "Input") == 0) {
        conf->note_input_name = arg2;
    } else if (ap_cstr_casecmp(arg1, "Output") == 0) {
        conf->note_output_name = arg2;
    } else {
        return apr_psprintf(cmd->pool, "Unknown ZstdFilterNote type '%s'", arg1);
    }

    return NULL;
}

static const char *set_compression_level(cmd_parms *cmd, void *dummy,
                                         const char *arg) {

    zstd_server_config_t *conf =
        ap_get_module_config(cmd->server->module_config, &zstd_module);

    int val = atoi(arg);
    if (val < ZSTD_minCLevel() || val > ZSTD_maxCLevel()) {
        return apr_psprintf(
            cmd->pool, 
            "ZstdCompressionLevel must be between %d and %d",
            ZSTD_minCLevel(), 
            ZSTD_maxCLevel()
        );
    }

    conf->compression_level = val;
    return NULL;
}

static const char *set_etag_mode(cmd_parms *cmd, void *dummy,
                                 const char *arg) {

    zstd_server_config_t *conf =
        ap_get_module_config(cmd->server->module_config, &zstd_module);

    if (ap_cstr_casecmp(arg, "AddSuffix") == 0) {
        conf->etag_mode = ETAG_MODE_ADDSUFFIX;
    } else if (ap_cstr_casecmp(arg, "NoChange") == 0) {
        conf->etag_mode = ETAG_MODE_NOCHANGE;
    } else if (ap_cstr_casecmp(arg, "Remove") == 0) {
        conf->etag_mode = ETAG_MODE_REMOVE;
    } else {
        return "ZstdAlterETag accepts only 'AddSuffix', 'NoChange' and 'Remove'";
    }

    return NULL;
}

static apr_status_t cleanup_ctx(void *data) {
    zstd_ctx_t *ctx = data;
    ZSTD_freeCCtx(ctx->cctx);
    ctx->cctx = NULL;
    return APR_SUCCESS;
}

static zstd_ctx_t *create_ctx(zstd_server_config_t* conf,
                              apr_bucket_alloc_t *alloc,
                              apr_pool_t *pool,
                              request_rec* r) {

    size_t rvsp;

    zstd_ctx_t *ctx = apr_pcalloc(pool, sizeof(*ctx));
    ctx->cctx = ZSTD_createCCtx();

    rvsp = ZSTD_CCtx_setParameter(ctx->cctx, ZSTD_c_compressionLevel,
                                  conf->compression_level);
    if (ZSTD_isError(rvsp)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(30301)
                      "[CREATE_CTX] ZSTD_c_compressionLevel(%d): %s",
                      conf->compression_level,
                      ZSTD_getErrorName(rvsp));
    }

    rvsp = ZSTD_CCtx_setParameter(ctx->cctx, ZSTD_c_nbWorkers, conf->workers);
    if (ZSTD_isError(rvsp)) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(30303)
                      "[CREATE_CTX] ZSTD_c_nbWorkers(%d): %s",
                      conf->workers,
                      ZSTD_getErrorName(rvsp));
    }

    apr_pool_cleanup_register(pool, ctx, cleanup_ctx, apr_pool_cleanup_null);

    ctx->bb = apr_brigade_create(pool, alloc);
    ctx->total_in = 0;
    ctx->total_out = 0;

    return ctx;
}

static apr_status_t process_bucket(zstd_ctx_t *ctx,
                                  ZSTD_EndDirective mode,
                                  const void *data,
                                  apr_size_t len,
                                  ap_filter_t *f) {

    size_t remaining;

    ZSTD_inBuffer input = { data, APR_SO_SNDBUF, 0 };
    size_t out_size = ZSTD_compressBound(APR_SO_SNDBUF);
    char *out_buffer = apr_palloc(f->r->pool, out_size);
    ZSTD_outBuffer output = { out_buffer, out_size, 0 };

    do {
        /*
         * https://facebook.github.io/zstd/zstd_manual.html#Chapter8
         */
        remaining = ZSTD_compressStream2(ctx->cctx, &output, &input, mode);
        if (ZSTD_isError(remaining)) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, f->r, APLOGNO(30305)
                "Error while processing bucket: %s",
                ZSTD_getErrorName(remaining));
            return APR_EGENERAL;
        }
    } while (remaining || (input.pos != input.size));

    if (output.pos > 0) {
        apr_bucket *b = apr_bucket_heap_create(out_buffer, output.pos,  NULL, ctx->bb->bucket_alloc);
        ctx->total_out += output.pos;
        APR_BRIGADE_INSERT_TAIL(ctx->bb, b);
    }

    ctx->total_in += len;

    return APR_SUCCESS;
}

static const char *get_content_encoding(request_rec *r) {

    const char *encoding;

    encoding = apr_table_get(r->headers_out, "Content-Encoding");
    if (encoding) {
        const char *err_enc;
        err_enc = apr_table_get(r->err_headers_out, "Content-Encoding");
        if (err_enc) {
            encoding = apr_pstrcat(r->pool, encoding, ",", err_enc, NULL);
        }
    } else {
        encoding = apr_table_get(r->err_headers_out, "Content-Encoding");
    }

    if (r->content_encoding) {
        encoding = encoding ? apr_pstrcat(r->pool, encoding, ",",
                                          r->content_encoding, NULL)
                            : r->content_encoding;
    }

    return encoding;
}

static apr_status_t compress_filter(ap_filter_t *f, apr_bucket_brigade *bb) {

    request_rec *r = f->r;
    zstd_ctx_t *ctx = f->ctx;
    apr_status_t rv;
    zstd_server_config_t *conf;

    if (APR_BRIGADE_EMPTY(bb)) {goto apr_success;}

    conf = ap_get_module_config(r->server->module_config, &zstd_module);

    //要在这里用 shm 方式去读响应的内容有多少。 内容大于多少时候再考虑压缩，就是嗯姬的那个最小压缩阈值
    apr_success:
    return APR_SUCCESS;
}

static apr_status_t zstd_post_config(
        apr_pool_t *p, 
        apr_pool_t *plog,
        apr_pool_t *ptemp, 
        server_rec *s
    ) {

    zstd_server_config_t *conf;
    conf = ap_get_module_config(s->module_config, &zstd_module);
    ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, APLOGNO(30307)
                 "mod_zstd cl:%d, wk:%d (v%s, zstd %s)",
                 conf->compression_level,
                 conf->workers,
                 MOD_ZSTD_VERSION,
                 ZSTD_versionString());
    ap_add_version_component(p, "mod_zstd/" MOD_ZSTD_VERSION);
    return OK;
}

/*
 *  2025年2月9日 输出到 mod_status 要直观点
 */
static int zstd_status_hook(request_rec* r, int flags)
{
    if (!(flags & AP_STATUS_SHORT)) {
        zstd_server_config_t* conf = ap_get_module_config(r->server->module_config, &zstd_module);

        ap_rputs("<style>.mod_zstd{display:grid;grid-template-columns:auto 1fr;} cite{cursor:pointer}</style>", r);
        ap_rputs("<hr>", r);
        ap_rputs("<h1>Zstd Module <cite onclick=\"javascript:window.open(this.innerText)\"> https://github.com/foglede/mod_zstd </cite></h1>", r);
        ap_rputs("<h2>Zstd Configuration Information</h2>",r);
        ap_rputs("<dl class=\"mod_zstd\">", r);
        ap_rprintf(r, "<dt>This mod_zstd Version&#65306;</dt><dd>%s</dd>", MOD_ZSTD_VERSION);
        ap_rprintf(r, "<dt>Zstd Library Version&#65306;</dt><dd>%s</dd>", ZSTD_versionString());
        ap_rprintf(r, "<dt>ZstdCompressionLevel&#65306;</dt><dd>%d</dd>", conf->compression_level);
        ap_rprintf(r, "<dt>ZstdAlterETag&#65306;</dt><dd>%d</dd>", conf->etag_mode);

        ap_rputs("</dl>", r);
    }

    return OK;
}

static const command_rec zstd_config_cmds[] = {

    AP_INIT_TAKE12("ZstdFilterNote", set_filter_note,                  NULL, RSRC_CONF,
                   "Set a note to report on compression ratio"),
    AP_INIT_TAKE1("ZstdCompressionLevel", set_compression_level,
                  NULL, RSRC_CONF,
                  "Compression level between min and max (higher level means "
                  "better compression but slower) MAX "), //ZSTD_maxCLevel()
    AP_INIT_TAKE1("ZstdAlterETag", set_etag_mode,
                  NULL, RSRC_CONF,
                  "Set how mod_zstd should modify ETag response headers: "
                  "'AddSuffix' (default), 'NoChange', 'Remove'"),
    {NULL}
};

static void register_hooks(apr_pool_t *p) {
    //ap_hook_handler(zstd_status_handler, NULL, NULL, APR_HOOK_MIDDLE);
    //ap_register_input_filter("ZSTD_COMPRESS", deflate_in_filter, NULL,AP_FTYPE_CONTENT_SET);
    //input可以实现多线程吧

    ap_register_output_filter("ZSTD_COMPRESS", compress_filter, NULL, AP_FTYPE_CONTENT_SET);
    APR_OPTIONAL_HOOK(ap, status_hook, zstd_status_hook, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_config(zstd_post_config, NULL, NULL, APR_HOOK_LAST);

}

AP_DECLARE_MODULE(zstd) = {
    STANDARD20_MODULE_STUFF,
    NULL,                      /* create per-directory config structure */
    NULL,                      /* merge per-directory config structures */
    create_server_config,      /* create per-server config structure */
    NULL,                      /* merge per-server config structures */
    zstd_config_cmds,          /* command apr_table_t */
    register_hooks             /* register hooks */
};