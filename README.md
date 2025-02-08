# This is a zstd compression implementation module in Apache Http Server 2.4+

### step 0：
https://github.com/facebook/zstd/tree/dev

    get comdline 【 zstd 】-v
 
### step 1: get me! ~

### step 2：  apt-get install apache2-dev   
 or Compile : https://github.com/apache/httpd

### step 3:
- apxs -c mod_zstd.c -lzstd
- apxs -i mod_zstd.la
- achieved file 【mod_zstd.so】

### step 4:
Add you httpd.conf file 

```xml
LoadModule zstd_module modules/mod_zstd.so
<Ifmodule mod_zstd.c>
AddOutputFilterByType ZSTD_COMPRESS text/plan text/html text/css application/wasm
 application/x-javascript application/json application/x-font-ttf application/vnd.ms-fontobject
AddOutputFilter ZSTD_COMPRESS js css wasm hdr cr3
</Ifmodule>
```

Tuning parameters
 > ZstdFilterNote - Set a note to report on compression ratio
 > ZstdCompressionLevel - Compression level between min and max (higher level means better compression but slower)
 > ZstdWindowSize - Window size between min and max (larger windows can improve compression, but require more memory)
 > ZstdAlterETag - Set how mod_zstd should modify ETag response headers: 'AddSuffix' (default), 'NoChange', 'Remove'
    
