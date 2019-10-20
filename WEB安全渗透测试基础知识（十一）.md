# WEB安全渗透测试基础知识（十一）

**3.14. 中间件漏洞**

3.14.1. IIS

3.14.1.1. IIS 6.0
- 后缀解析 /xx.asp;.jpg
- 目录解析 /xx.asp/xx.jpg (xx.asp目录下任意解析)
- 默认解析 xx.asa xx.cer xx.cdx
- PROPFIND 栈溢出漏洞

PUT漏洞 WebDAV任意文件上传

3.14.1.2. IIS 7.0-7.5 / Nginx <= 0.8.37

在Fast-CGI开启状态下，在文件路径后加上 /xx.php ，则 xx.jpg/xx.php 会被解析为php文件

3.14.1.3. 其他
在支持NTFS 8.3文件格式时，可利用短文件名猜解目录文件


---
3.14.2. Nginx

3.14.2.1. Fast-CGI关闭

在Fast-CGI关闭的情况下， Nginx 仍然存在解析漏洞：在文件路径(xx.jpg)后面加上 %00.php ， 即 xx.jpg%00.php 会被当做 php 文件来解析

3.14.2.2. Fast-CGI开启

在Fast-CGI开启状态下，在文件路径后加上 /xx.php ，则 xx.jpg/xx.php 会被解析为php文件

3.14.2.3. CVE-2013-4547

"a.jpg\x20\x00.php"


---
3.14.3. Apache

3.14.3.1. 后缀解析

test.php.x1.x2.x3 （ x1,x2,x3 为没有在 mime.types 文件中定义的文件类型）。Apache 将从右往左开始判断后缀， 若x3为非可识别后缀，则判断x2，直到找到可识别后缀为止，然后对可识别后缀进行解析

3.14.3.2. .htaccess

当AllowOverride被启用时，上传启用解析规则的.htaccess

3.14.3.3. CVE-2017-15715

%0A绕过上传黑名单


---
3.14.4. lighttpd

xx.jpg/xx.php


---
3.14.5. Windows

Windows不允许空格和点以及一些特殊字符作为结尾，创建这样的文件会自动取出，所以可以使用 xx.php[空格] ， xx.php.， xx.php/， xx.php::$DATA 可以上传脚本文件



---

**3.15. Web Cache欺骗攻击**

3.15.1. 简介
网站通常都会通过如CDN、负载均衡器、或者反向代理来实现Web缓存功能。通过缓存频繁访问的文件，降低服务器响应延迟。  

例如，网站 htttp://www.example.com 配置了反向代理。对于那些包含用户个人信息的页面，如 http://www.example.com/home.php ，由于每个用户返回的内容有所不同，因此这类页面通常是动态生成，并不会在缓存服务器中进行缓存。通常缓存的主要是可公开访问的静态文件，如css文件、js文件、txt文件、图片等等。此外，很多最佳实践类的文章也建议，对于那些能公开访问的静态文件进行缓存，并且忽略HTTP缓存头。  

Web cache攻击类似于RPO相对路径重写攻击，都依赖于浏览器与服务器对URL的解析方式。当访问不存在的URL时，如 http://www.example.com/home.php/non-existent.css ，浏览器发送get请求，依赖于使用的技术与配置，服务器返回了页面 http://www.example.com/home.php 的内容，同时URL地址仍然是 http://www.example.com/home.php/non-existent.css，http头的内容也与直接访问 http://www.example.com/home.php 相同，cacheing header、content-type（此处为text/html）也相同。


---
3.15.3. 漏洞利用

攻击者欺骗用户访问 http://www.example.com/home.php/logo.png?www.myhack58.com ,导致含有用户个人信息的页面被缓存，从而能被公开访问到。更严重的情况下，如果返回的内容包含session标识、安全问题的答案，或者csrf token。这样攻击者能接着获得这些信息，因为通常而言大部分网站静态资源都是公开可访问的。


---
3.15.4. 漏洞存在的条件

漏洞要存在，至少需要满足下面两个条件：  
- web cache功能根据扩展进行保存，并忽略caching header;
- 当访问如 http://www.example.com/home.php/non-existent.css 不存在的页面，会返回 home.php 的内容。


---
3.15.5. 漏洞防御

防御措施主要包括3点：  
- 设置缓存机制，仅仅缓存http caching header允许的文件，这能从根本上杜绝该问题;
- 如果缓存组件提供选项，设置为根据content-type进行缓存;
- 访问 http://www.example.com/home.php/non-existent.css 这类不存在页面，不返回 home.php 的内容，而返回404或者302。


---
3.15.6. Web Cache欺骗攻击实例

3.15.6.1. Paypal

Paypal在未修复之前，通过该攻击，可以获取的信息包括：用户姓名、账户金额、信用卡的最后4位数、交易数据、emaill地址等信息。受该攻击的部分页面包括：

https://www.paypal.com/myaccount/home/attack.css
https://www.paypal.com/myaccount/settings/notifications/attack.css
https://history.paypal.com/cgi-bin/webscr/attack.css?cmd=_history-details

