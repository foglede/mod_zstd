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
