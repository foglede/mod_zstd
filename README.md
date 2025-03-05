# This is a zstd compression implementation module in Apache Http Server 2.4+

### step 0：
https://github.com/facebook/zstd/tree/dev

    get comdline :
    zstd -v
 
### step 1: get me! [git Source code](https://github.com/foglede/mod_zstd/)

### step 2：  apt-get install apache2-dev   
 or Compile : https://github.com/apache/httpd

### step 3:
- apxs -cia mod_zstd.c -lzstd
- achieved file mod_zstd.so 

### step 4:
edit you httpd.conf file 

```xml
LoadModule zstd_module modules/mod_zstd.so
<Ifmodule mod_zstd.c>
AddOutputFilterByType ZSTD_COMPRESS text/plan text/html text/css application/wasm
 application/x-javascript application/json application/x-font-ttf application/vnd.ms-fontobject
AddOutputFilter ZSTD_COMPRESS js css wasm hdr cr3
</Ifmodule>
```

Windows binaries here : [https://github.com/nono303/mod_zstd](https://github.com/nono303/mod_zstd/releases)

He made some changes for compatibility, but he did not fork the code

# Tuning parameters
 - ZstdFilterNote - Set a note to report on compression ratio
 - ZstdCompressionLevel - Compression level between min>0 and max (higher level means better compression but slower),
proposal value ZstdCompressionLevel <= 19 , Max 23
 - ZstdWindowSize - Window size between min and max (larger windows can improve compression, but require more memory)
 - ZstdAlterETag - Set how mod_zstd should modify ETag response headers: 'AddSuffix' (default), 'NoChange', 'Remove'

After some statistics and observations, I suggest AddOutputFilterByType order as follows

 AddOutputFilterByType ZSTD_COMPRESS;BROTLI_COMPRESS;DEFLATE …………………………
 
Its order is almost equal to RFC_NUM in reverse order：

ZSTD = RFC 8478

BROTLI = RFC 7932

 GZIP = RFC 1952
 
DEFLATE = RFC 1951

Almost no one has discovered this miracle, and there is no clear consensus or regulations.  

In this case, the most appropriate compression scheme is entered regardless of the visitor's browser compatibility.

this my Tuning “Sutra”

if u use nginx,or caddy ,or more , It does not have such complete compatibility, and you must write “IF” in the configuration file.

