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

# Windows Version Zstd module Releases
Windows binaries : [https://github.com/nono303/mod_zstd](https://github.com/nono303/mod_zstd/releases)

 @nono303 did not fork the my code, @nono303 stress His source code is cloned from [Br](https://github.com/kjdev/apache-mod-brotli) compression

we still have the same inspiration 

# Tuning parameters
 - ZstdCompressionLevel - Compression level between min>0 and max (higher level means better compression but slower),
proposal value ZstdCompressionLevel <= 19 , Max 23
 - ZstdAlterETag - Set how mod_zstd should modify ETag response headers: 'AddSuffix' (default), 'NoChange', 'Remove'
 - ZstdCompressionStrategy - Set the compression strategy: 'fast' (default), 'high' 
 - ZSTDChainLog - Set the chain log: '8'    

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

