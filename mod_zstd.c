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
#include "ap_provider.h"     
#include "apr_optional.h"    
#include "apr_optional_hooks.h"
#include "mod_status.h"

#include <zstd.h>
#include "mod_zstd.h"

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
    const char* note_ratio_name;
    const char* note_input_name;
    const char* note_output_name;
} zstd_server_config_t;

/***
 * @see https://raw.githack.com/facebook/zstd/release/doc/zstd_manual.html#Chapter2
 */
static void* create_server_config(apr_pool_t* p, server_rec* s)
{
    zstd_server_config_t* conf = apr_pcalloc(p, sizeof(*conf));

    conf->compression_level = 7;  // 默认
    conf->window_size = 128;

    conf->strategy = ZSTD_fast;
    conf->etag_mode = ETAG_MODE_ADDSUFFIX;

    return conf;
}

static const char* set_filter_note(cmd_parms* cmd, void* dummy,
    const char* arg1, const char* arg2)
{
    zstd_server_config_t* conf =
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

static const char* set_compression_level(cmd_parms* cmd, void* dummy,
    const char* arg)
{
    zstd_server_config_t* conf =
        ap_get_module_config(cmd->server->module_config, &zstd_module);
    int val = atoi(arg);

    if (val < ZSTD_minCLevel() || val > ZSTD_maxCLevel()) {
        return apr_psprintf(cmd->pool, "ZstdCompressionLevel must be between %d and %d",
            ZSTD_minCLevel(), ZSTD_maxCLevel());
    }
    //最好不要中断 reutrn 直接 log warn 就行，但是得  v1.5.0+ 版本才行 使用 ZSTD_CLEVEL_DEFAULT  
    conf->compression_level = val;
    return NULL;
}

static const char* set_window_size(cmd_parms* cmd, void* dummy,
    const char* arg)
{
    zstd_server_config_t* conf =
        ap_get_module_config(cmd->server->module_config, &zstd_module);
    int val = atoi(arg);

    if (val < 0 || val > 101) {
        return apr_psprintf(cmd->pool, "ZstdWindowSize = (ZSTD_c_windowLog) must be between %d and %d",
            0, 101);
    }


    conf->window_size = val;
    return NULL;
}

static const char* set_etag_mode(cmd_parms* cmd, void* dummy,
    const char* arg)
{
    zstd_server_config_t* conf =
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
    ZSTD_CCtx* cctx;
    apr_bucket_brigade* bb;
    apr_off_t total_in;
    apr_off_t total_out;
} zstd_ctx_t;

static apr_status_t cleanup_ctx(void* data)
{
    zstd_ctx_t* ctx = data;

    ZSTD_freeCCtx(ctx->cctx);
    ctx->cctx = NULL;
    return APR_SUCCESS;
}

static zstd_ctx_t* create_ctx(int compression_level,
    int window_size,
    apr_bucket_alloc_t* alloc,
    apr_pool_t* pool)
{
    zstd_ctx_t* ctx = apr_pcalloc(pool, sizeof(*ctx));

    ctx->cctx = ZSTD_createCCtx();
    ZSTD_CCtx_setParameter(ctx->cctx, ZSTD_c_compressionLevel, compression_level);
    ZSTD_CCtx_setParameter(ctx->cctx, ZSTD_c_windowLog, window_size);
    apr_pool_cleanup_register(pool, ctx, cleanup_ctx, apr_pool_cleanup_null);

    ctx->bb = apr_brigade_create(pool, alloc);
    ctx->total_in = 0;
    ctx->total_out = 0;

    return ctx;
}

static apr_status_t process_chunk(zstd_ctx_t* ctx,
    const void* data,
    apr_size_t len,
    ap_filter_t* f)
{
    ZSTD_inBuffer input = { data, len, 0 };
    size_t out_size = ZSTD_compressBound(len);
    char* out_buffer = apr_palloc(f->r->pool, out_size);
    ZSTD_outBuffer output = { out_buffer, out_size, 0 };

    size_t remaining = ZSTD_compressStream2(ctx->cctx, &output, &input, ZSTD_e_continue);
    if (ZSTD_isError(remaining)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, f->r, APLOGNO(03459)
            "Error while compressing data: %s",
            ZSTD_getErrorName(remaining));
        return APR_EGENERAL;
    }

    if (output.pos > 0) {
        apr_bucket* b = apr_bucket_heap_create(out_buffer, output.pos, NULL,
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

static apr_status_t flush_old(zstd_ctx_t* ctx,
    ZSTD_EndDirective mode,
    ap_filter_t* f)
{
    ZSTD_inBuffer input = { NULL, 0, 0 };
    size_t out_size = ZSTD_compressBound(ZSTD_CStreamInSize());
    char* out_buffer = apr_palloc(f->r->pool, out_size);
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
            apr_bucket* b = apr_bucket_heap_create(out_buffer, output.pos, NULL,
                ctx->bb->bucket_alloc);
            APR_BRIGADE_INSERT_TAIL(ctx->bb, b);
            ctx->total_out += output.pos;
        }
    } while (remaining > 0);

    return APR_SUCCESS;
}

static apr_status_t flush(zstd_ctx_t* ctx, ZSTD_EndDirective mode,  ap_filter_t* f)
{
    ZSTD_inBuffer input = { NULL, 0, 0 };
    size_t out_size = ZSTD_compressBound(ZSTD_CStreamInSize());
    char* out_buffer = apr_palloc(f->r->pool, out_size);
    ZSTD_outBuffer output = { out_buffer, out_size, 0 };
    size_t remaining;
    if(mode == ZSTD_e_end){
      remaining = ZSTD_endStream(ctx->cctx, &output);
    }

    if(mode == ZSTD_e_flush){
      remaining = ZSTD_compressStream2(ctx->cctx, &output, &input, ZSTD_e_flush);
    }

    if (output.pos > 0) {
        apr_bucket* b = apr_bucket_heap_create(out_buffer, output.pos, NULL, ctx->bb->bucket_alloc);
        
        APR_BRIGADE_INSERT_TAIL(ctx->bb, b);
        ctx->total_out += output.pos;
    }

    return APR_SUCCESS;
    
}

static apr_status_t flush_o(zstd_ctx_t* ctx,
    ZSTD_EndDirective mode,
    ap_filter_t* f)
{
    size_t out_size = ZSTD_compressBound(ZSTD_CStreamInSize());
    char* out_buffer = apr_palloc(f->r->pool, out_size);
    ZSTD_outBuffer output = { out_buffer, out_size, 0 };
    size_t remaining;

    if (mode == ZSTD_e_end) {
        remaining = ZSTD_endStream(ctx->cctx, &output);
    } else {
        remaining = ZSTD_flushStream(ctx->cctx, &output);
    }

    if (ZSTD_isError(remaining)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, f->r, APLOGNO(03460)
            "Error while flushing data: %s",
            ZSTD_getErrorName(remaining));
        return APR_EGENERAL;
    }

    if (output.pos > 0) {
        apr_bucket* b = apr_bucket_heap_create(out_buffer, output.pos, NULL,
            ctx->bb->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(ctx->bb, b);
        ctx->total_out += output.pos;
    }

    return APR_SUCCESS;
}

static const char* get_content_encoding(request_rec* r)
{
    const char* encoding;

    encoding = apr_table_get(r->headers_out, "Content-Encoding");
    if (encoding) {
        const char* err_enc;

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

static apr_status_t compress_filter(ap_filter_t* f, apr_bucket_brigade* bb)
{
    request_rec* r = f->r;
    zstd_ctx_t* ctx = f->ctx;
    apr_status_t rv;
    zstd_server_config_t* conf;

    if (APR_BRIGADE_EMPTY(bb)) {
        return APR_SUCCESS;
    }

    conf = ap_get_module_config(r->server->module_config, &zstd_module);

    if (!ctx) {
        const char* encoding;
        const char* token;
        const char* accepts;
        const char* q = NULL;

        if (r->main || r->status == HTTP_NO_CONTENT
            || apr_table_get(r->subprocess_env, "no-zstd")
            || apr_table_get(r->headers_out, "Content-Range")) {
            ap_remove_output_filter(f);
            return ap_pass_brigade(f->next, bb);
        }

        encoding = get_content_encoding(r);

        if (encoding) {
            const char* tmp = encoding;

            token = ap_get_token(r->pool, &tmp, 0);
            // 这个算是Apache 的私有协议了。。
            while (token && *token) {
                //strcmp(token, "br")
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
        }
        else {
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
            const char* etag = apr_table_get(r->headers_out, "ETag");

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
        apr_bucket* e = APR_BRIGADE_FIRST(bb);

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
                    int ratio = (int)(ctx->total_out * 100 / ctx->total_in);
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
            const char* data;
            apr_size_t len;
            //dev 0.3
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
        ap_rprintf(r, "<dt>ZstdWindowSize&#65306;</dt><dd>%d</dd>", conf->window_size);
        ap_rprintf(r, "<dt>ZstdAlterETag&#65306;</dt><dd>%d</dd>", conf->etag_mode);

        ap_rputs("</dl>", r);
    }
    return OK;
}

static void register_hooks(apr_pool_t* p)
{
    //ap_hook_handler(zstd_status_handler, NULL, NULL, APR_HOOK_MIDDLE);
    //ap_register_input_filter("ZSTD_COMPRESS", deflate_in_filter, NULL,AP_FTYPE_CONTENT_SET);
    //input可以实现多线程吧
    ap_register_output_filter("ZSTD_COMPRESS", compress_filter, NULL, AP_FTYPE_CONTENT_SET);

    APR_OPTIONAL_HOOK(ap, status_hook, zstd_status_hook, NULL, NULL, APR_HOOK_MIDDLE);
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
                  "Maximum allowed back-reference distance, expressed as power of 2."),
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
