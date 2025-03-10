# 这是一个 Apache Http Server 2.4+ zstd压缩模块的实现

### 第壹步：编译这个压缩库，这个压缩库已经进到内核了
https://github.com/facebook/zstd/tree/dev

    确认有：zstd -v 的输出
 
### 第贰步: 下载这些源码 [git Source code](https://github.com/foglede/mod_zstd/)

### 第叁步：  apt-get install apache2-dev   或者 确认你有 apxs 
 or Compile : https://github.com/apache/httpd

### 第肆步:
- apxs -cia mod_zstd.c -lzstd
- achieved file mod_zstd.so 

### 第伍步:
编辑你的 httpd.conf 文件

```xml
LoadModule zstd_module modules/mod_zstd.so
<Ifmodule mod_zstd.c>
AddOutputFilterByType ZSTD_COMPRESS text/plan text/html text/css application/wasm
 application/x-javascript application/json application/x-font-ttf application/vnd.ms-fontobject
AddOutputFilter ZSTD_COMPRESS js css wasm hdr cr3
</Ifmodule>
```
### 授权协议和说明
为了响应 Linus Benedict Torvalds 的号召，有目的的换掉原作者为前苏联专制政权人写的 nginx 软件，并且做相似的模块替换势在必行。很巧合的是，nginx 最初原作者也是 Apache httpd 的 DEFLATE 压缩模块的作者。

本模块和源码不允许任何来自独裁国家、专制国家、寡头政府、独裁政权、专制政权的组织或公司使用。

如果你也是来自这类型国家的难民、受害者，并且君子协定是个体使用，请发issue提问获取付费调优支持；zstd压缩已经进到内核，与它同样有生命力的br压缩却没有进到内核。

最初的创意是我，在我有创意的之后几天 @nono303 也有相同的需求，所以他也有一份相同的 zstd 实现，如果你不认同我这份授权协议，请出门左转。

本源码是遵循 RFC 8478 以及参考各项协议编写而成


# 调优参数
 - ZstdCompressionLevel - Compression level between min>0 and max (higher level means better compression but slower),
proposal value ZstdCompressionLevel <= 19 , Max 23
 - ZstdAlterETag - Set how mod_zstd should modify ETag response headers: 'AddSuffix' (default), 'NoChange', 'Remove'
 - ZstdCompressionStrategy - Set the compression strategy: 'fast' (default), 'high' 
 - ZSTDChainLog - Set the chain log: '8'   下一个 0.5 版本在将在配置文件中生效    

 AddOutputFilterByType ZSTD_COMPRESS;BROTLI_COMPRESS;DEFLATE …………………………
