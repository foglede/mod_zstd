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
#include <zstd_errors.h>
#include "mod_zstd.h"

#ifdef _WIN32
#include <windows.h>
#elif defined(unix) || defined(__unix__) || defined(__APPLE__)
#include <unistd.h>
#endif

module AP_MODULE_DECLARE_DATA zstd_module;

static void *create_server_config(apr_pool_t *p, server_rec *s) {

    zstd_server_config_t *conf = apr_pcalloc(p, sizeof(*conf));

#ifdef _SC_NPROCESSORS_ONLN
    conf->workers = sysconf(_SC_NPROCESSORS_ONLN) ;
#elif _WIN32
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    conf->workers = sysInfo.dwNumberOfProcessors;
#endif   

    if ( conf->workers < 0 ) {
        conf->workers = 0;
    }

    conf->compression_level = 17;
    conf->etag_mode = ETAG_MODE_ADDSUFFIX;
    conf->strategy = ZSTD_greedy;
    
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

    apr_int32_t val = atoi(arg);
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

/** 设置压缩速度 **/
static const char *set_compression_strategy(cmd_parms *cmd, void *dummy, const char *arg) {
    
    zstd_server_config_t *conf = ap_get_module_config(cmd->server->module_config, &zstd_module);

    apr_int32_t strategy = atoi(arg);//abs
    if (strategy < ZSTD_fast || strategy > 9) {
        return apr_psprintf(
            cmd->pool, 
            "ZstdCompressionStrategy must be between %d and %d",
            ZSTD_fast, 
            9
        );
    }
    conf->strategy = strategy;
    return NULL;
}

static const char *set_etag_mode(cmd_parms *cmd, void *dummy,  const char *arg) {

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

    rvsp = ZSTD_CCtx_setParameter(ctx->cctx, ZSTD_c_compressionLevel, conf->compression_level);
    if (ZSTD_isError(rvsp)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(30308)
                      "[zstd_setPar] ZSTD_c_compressionLevel(%d): %s",
                      conf->compression_level,
                      ZSTD_getErrorName(rvsp));
    }
    
    // rvsp = ZSTD_CCtx_setParameter(ctx->cctx, ZSTD_c_chainLog, (apr_int32_t) (conf->workers * 2));
    // if (ZSTD_isError(rvsp)) {
    //     ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(30302)
    //                   "[zstd_setPar] ZSTD_c_chainLog(%d): %s",
    //                    (conf->workers * 2), //conf->chainLog
    //                   ZSTD_getErrorName(rvsp));
    // }

    rvsp = ZSTD_CCtx_setParameter(ctx->cctx, ZSTD_c_strategy, conf->strategy);
    if (ZSTD_isError(rvsp)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(30301)
                      "[zstd_setPar] ZSTD_c_strategy(%d): %s",
                      conf->strategy,
                      ZSTD_getErrorName(rvsp));
    }

    rvsp = ZSTD_CCtx_setParameter(ctx->cctx, ZSTD_c_nbWorkers, conf->workers);
    if (ZSTD_isError(rvsp)) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(30303)
                      "[zstd_setPar] ZSTD_c_nbWorkers(%d): %s",
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

    ZSTD_inBuffer input = { data, len, 0 };
    size_t out_size = ZSTD_compressBound(len);
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
        encoding = encoding ? 
        apr_pstrcat(r->pool, encoding, ",", r->content_encoding, NULL) : 
        r->content_encoding ;
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

        /* Let's see what our current Content-Encoding is. */
        encoding = get_content_encoding(r);
        if (encoding) {
            const char *tmp = encoding;
            token = ap_get_token(r->pool, &tmp, 0);
            while (token && *token) {
                if (strcmp(token, "identity") != 0 &&
                    strcmp(token, "7bit") != 0 &&
                    strcmp(token, "8bit") != 0 &&
                    strcmp(token, "binary") != 0) {
                    /* The data is already encoded, do nothing. */
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

        /* Find the qvalue, if provided */
        if (*accepts) {
            while (*accepts == ';') {
                ++accepts;
            }
            q = ap_get_token(r->pool, &accepts, 1);
            ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r,
                          "token: '%s' - q: '%s'", token ? token : "NULL", q);
        }

        /* No acceptable token found or q=0 */
        if (!token || token[0] == '\0' ||
            (q && strlen(q) >= 3 && strncmp("q=0.000", q, strlen(q)) == 0)) {
            ap_remove_output_filter(f);
            return ap_pass_brigade(f->next, bb);
        }

        /* If the entire Content-Encoding is "identity", we can replace it. */
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
        } else if (conf->etag_mode == ETAG_MODE_ADDSUFFIX) {
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

        /* For 304 responses, we only need to send out the headers. */
        if (r->status == HTTP_NOT_MODIFIED) {
            ap_remove_output_filter(f);
            return ap_pass_brigade(f->next, bb);
        }

        ctx = create_ctx(conf,f->c->bucket_alloc, r->pool, f->r);
        f->ctx = ctx;
    }

    apr_bucket *e;
    while ((e = APR_BRIGADE_FIRST(bb)) != APR_BRIGADE_SENTINEL(bb)) {

        if (r->header_only && r->bytes_sent) {
            ap_remove_output_filter(f);
            return ap_pass_brigade(f->next, bb);
        }

        if (APR_BUCKET_IS_EOS(e)) {
            //zstd手册写end反正都是阻塞的，我只是优化几个纳秒的速度
            //size_t rvsp = ZSTD_CCtx_setParameter(ctx->cctx, ZSTD_c_nbWorkers, 0);
            // if (ZSTD_isError(rvsp)) {
            //     ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(30301)
            //     "[zstd_setPar] EOS ZSTD_c_nbWorkers(%d): %s,error",
            //     conf->strategy,
            //     ZSTD_getErrorName(rvsp));
            // }

            rv = process_bucket(ctx, ZSTD_e_end, NULL, 0, f);
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
                    apr_int32_t ratio = (apr_int32_t) (ctx->total_out * 100 / ctx->total_in);

                    apr_table_setn(r->notes, conf->note_ratio_name,
                                   apr_itoa(r->pool, ratio));
                } else {
                    apr_table_setn(r->notes, conf->note_ratio_name, "-");
                }
            }

            APR_BUCKET_REMOVE(e);
            APR_BRIGADE_INSERT_TAIL(ctx->bb, e);

            rv = ap_pass_brigade(f->next, ctx->bb);
            apr_brigade_cleanup(ctx->bb);
            apr_pool_cleanup_run(r->pool, ctx, cleanup_ctx);
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                          "%s [c:%d w:%d] %s:%ld %s:%ld %s:%ld",
                          r->the_request,
                          conf->compression_level, conf->workers,
                          conf->note_input_name, ctx->total_in,
                          conf->note_output_name, ctx->total_out,
                          conf->note_ratio_name, 
                          (apr_int64_t) (ctx->total_out * 100 / ctx->total_in));
            return rv;

        } else if (APR_BUCKET_IS_FLUSH(e)) {
            APR_BUCKET_REMOVE(e);
            APR_BRIGADE_INSERT_TAIL(ctx->bb, e);

            /* 直接调用flush快得多 */
            //ZSTD_flushStream(ctx->cctx,NULL);

            rv = process_bucket(ctx, ZSTD_e_flush, NULL, 0, f);
            if (rv != APR_SUCCESS) {
                return rv;
            }

            rv = ap_pass_brigade(f->next, ctx->bb);
            apr_brigade_cleanup(ctx->bb);
            if (rv != APR_SUCCESS) {
                return rv;
            }

        } else if (APR_BUCKET_IS_METADATA(e)) {
            APR_BUCKET_REMOVE(e);
            APR_BRIGADE_INSERT_TAIL(ctx->bb, e);

        } else {
            const char *data;
            apr_size_t len;

            rv = apr_bucket_read(e, &data, &len, APR_NONBLOCK_READ);
            if (rv != APR_SUCCESS) {
                return rv;
            }

            rv = process_bucket(ctx, ZSTD_e_flush, data, len, f);
            if (rv != APR_SUCCESS) {
                return rv;
            }

            rv = ap_pass_brigade(f->next, ctx->bb);
            apr_brigade_cleanup(ctx->bb);
            if (rv != APR_SUCCESS) {
                return rv;
            }

            apr_bucket_delete(e);
        }
    }
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
static apr_int32_t zstd_status_hook(request_rec* r, apr_int32_t flags)
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
         ap_rprintf(r, "<dt>ZstdCompressionStrategy&#65306;</dt><dd>%d</dd>", conf->strategy);
        ap_rprintf(r, "<dt>ZstdWorkers&#65306;</dt><dd>%d</dd>", conf->workers);
        
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
    AP_INIT_TAKE1("ZstdCompressionStrategy", set_compression_strategy,
                  NULL, RSRC_CONF,
                  "Compression strategy between 1 and 9 (higher means "
                  "better compression but slower)"),
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