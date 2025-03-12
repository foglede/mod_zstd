#define MOD_ZSTD_VERSION "0.7"

typedef enum {
    ETAG_MODE_ADDSUFFIX = 0,
    ETAG_MODE_NOCHANGE = 1,
    ETAG_MODE_REMOVE = 2
} etag_mode_e;
	
typedef struct zstd_server_config_t {
    apr_int32_t compression_level,strategy,workers;
    etag_mode_e etag_mode;
    const char *note_ratio_name;
    const char *note_input_name;
    const char *note_output_name;
} zstd_server_config_t;

typedef struct zstd_ctx_t {
    ZSTD_CCtx *cctx;
    apr_bucket_brigade *bb;
    apr_off_t total_in;
    apr_off_t total_out;
} zstd_ctx_t;
