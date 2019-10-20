# WEB安全渗透测试基础知识（二）

**1.3. 域名系统**


1.3.1. 域名系统工作原理

DNS解析过程是递归查询的，具体过程如下： 
用户要访问域名www.example.com时，先查看本机hosts是否有记录或者本机是否有DNS缓存，如果有，直接返回结果，否则向递归服务器查询该域名的IP地址
递归缓存为空时，首先向根服务器查询com顶级域的IP地址
根服务器告知递归服务器com顶级域名服务器的IP地址
递归向com顶级域名服务器查询负责example.com的权威服务器的IP
com顶级域名服务器返回相应的IP地址
递归向example.com的权威服务器查询www.example.com的地址记录
权威服务器告知www.example.com的地址记录
递归服务器将查询结果返回客户端 
 


------------

1.3.2. 根服务器

根服务器是DNS的核心，负责互联网顶级域名的解析，用于维护域的权威信息，并将DNS查询引导到相应的域名服务器。 
根服务器在域名树中代表最顶级的 . 域， 一般省略。 
13台IPv4根服务器的域名标号为a到m，即a.root-servers.org到m.root-servers.org，所有服务器存储的数据相同，仅包含ICANN批准的TLD域名权威信息。 

------------

1.3.3. 权威服务器
权威服务器上存储域名Zone文件，维护域内域名的权威信息，递归服务器可以从权威服务器获得DNS查询的资源记录。 
权威服务器需要在所承载的域名所属的TLD管理局注册，同一个权威服务器可以承载不同TLD域名，同一个域也可以有多个权威服务器。

------------

1.3.4. 递归服务器
递归服务器负责接收用户的查询请求，进行递归查询并响应用户查询请求。在初始时递归服务器仅有记录了根域名的Hint文件。 

------------

1.3.5. DGA
DGA（Domain Generate Algorithm，域名生成算法）是一种利用随机字符来生成C&C域名，从而逃避域名黑名单检测的技术手段，常见于botnet中。

------------

1.3.6. DNS隧道
DNS隧道工具将进入隧道的其他协议流量封装到DNS协议内，在隧道上传输。这些数据包出隧道时进行解封装，还原数据。 

------------



**1.4. HTTP标准 **

1.4.1.1. 请求报文格式

```

<method><request-URL><version> 
<headers> 

<entity-body>

```

------------

1.4.1.2. 响应报文格式
```
<version><status><reason-phrase> 
<headers> 

<entity-body>
```


------------
1.4.1.3.字段解释
```
method
HTTP动词
常见方法：HEAD / GET / POST / PUT / DELETE / PATCH / OPTIONS / TRACE
扩展方法：LOCK / MKCOL / COPY / MOVE
version
报文使用的HTTP版本
格式为HTTP/<major>.<minor>
url
<scheme>://<user>:<password>@<host>:<port>/<path>
```

------------

1.4.2. 请求头列表

- Accept
指定客户端能够接收的内容类型
```
Accept: text/plain, text/html
```
- Accept-Charset
浏览器可以接受的字符编码集
```
Accept-Charset: iso-8859-5
```
- Accept-Encoding
指定浏览器可以支持的web服务器返回内容压缩编码类型
```
Accept-Encoding: compress, gzip
```
- Accept-Language
浏览器可接受的语言
```
Accept-Language: en,zh
```
- Accept-Ranges
可以请求网页实体的一个或者多个子范围字段
```
Accept-Ranges: bytes
```
- Authorization
HTTP授权的授权证书
```
Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==
```
- Cache-Control 
指定请求和响应遵循的缓存机制 Cache-Control: no-cache

- Connection
表示是否需要持久连接 // HTTP 1.1默认进行持久连接
Connection: close

- Cookie
HTTP请求发送时，会把保存在该请求域名下的所有cookie值一起发送给web服务器
Cookie: role=admin;ssid=1

- Content-Length
请求的内容长度
Content-Length: 348 

- Content-Type
请求的与实体对应的MIME信息
```
Content-Type: application/x-www-form-urlencoded
```

- Date
请求发送的日期和时间
Date: Tue, 15 Nov 2010 08:12:31 GMT

- Expect
请求的特定的服务器行为
Expect: 100-continue

- From
发出请求的用户的Email
From: user@email.com

- Host
指定请求的服务器的域名和端口号
Host: www.github.com

- If-Match
只有请求内容与实体相匹配才有效
If-Match: “737060cd8c284d8af7ad3082f209582d”

- If-Modified-Since
如果请求的部分在指定时间之后被修改则请求成功，未被修改则返回304代码
If-Modified-Since: Sat, 29 Oct 2018 19:43:31 GMT

- If-None-Match
如果内容未改变返回304代码，参数为服务器先前发送的Etag，与服务器回应的Etag比较判断是否改变
If-None-Match: “737060cd8c284d8af7ad3082f209582d”

- If-Range
如果实体未改变，服务器发送客户端丢失的部分，否则发送整个实体。参数也为Etag
If-Range: “737060cd8c284d8af7ad3082f209582d”

- If-Unmodified-Since
只在实体在指定时间之后未被修改才请求成功
If-Unmodified-Since: Sat, 29 Oct 2010 19:43:31 GMT

- Max-Forwards
限制信息通过代理和网关传送的时间
Max-Forwards: 10

- Pragma
用来包含实现特定的指令
Pragma: no-cache

- Proxy-Authorization
连接到代理的授权证书
Proxy-Authorization:BasicQWxhZGRpbjpvcGVuIHNlc2FtZQ===

- Range
只请求实体的一部分，指定范围
Range: bytes=500-999

- Referer
先前网页的地址，当前请求网页紧随其后,即来路
Referer: http://www.agesec.com/5210.html

- TE
客户端愿意接受的传输编码，并通知服务器接受接受尾加头信息 TE: trailers,deflate;q=0.5

- Upgrade
向服务器指定某种传输协议以便服务器进行转换（如果支持） Upgrade: HTTP/2.0, SHTTP/1.3, IRC/6.9, RTA/x11

- User-Agent
User-Agent的内容包含发出请求的用户信息
User-Agent: Mozilla/5.0 (Linux; X11)

- Via
通知中间网关或代理服务器地址，通信协议
Via: 1.0 fred, 1.1 nowhere.com (Apache/1.1)

- Warning
关于消息实体的警告信息
Warn: 199 Miscellaneous warning


------------

1.4.3. 响应头列表
- Accept-Ranges
表明服务器是否支持指定范围请求及哪种类型的分段请求 Accept-Ranges: bytes

- Age
从原始服务器到代理缓存形成的估算时间（以秒计，非负） Age: 12

- Allow
对某网络资源的有效的请求行为，不允许则返回405
Allow: GET, HEAD

- Cache-Control
告诉所有的缓存机制是否可以缓存及哪种类型
Cache-Control: no-cache

- Content-Encoding
web服务器支持的返回内容压缩编码类型。
Content-Encoding: gzip

- Content-Language
响应体的语言
Content-Language: en,zh

- Content-Length
响应体的长度
Content-Length: 348

- Content-Location
请求资源可替代的备用的另一地址
Content-Location: /index.htm

- Content-MD5
返回资源的MD5校验值
Content-MD5: Q2hlY2sgSW50ZWdyaXR5IQ==

- Content-Range
在整个返回体中本部分的字节位置
Content-Range: bytes 21010-47021/47022

- Content-Type
返回内容的MIME类型
Content-Type: text/html; charset=utf-8

- Date
原始服务器消息发出的时间
Date: Tue, 15 Nov 2010 08:12:31 GMT

- ETag
请求变量的实体标签的当前值
ETag: “737060cd8c284d8af7ad3082f209582d”

- Expires
响应过期的日期和时间
Expires: Thu, 01 Dec 2010 16:00:00 GMT

- Last-Modified
请求资源的最后修改时间
Last-Modified: Tue, 15 Nov 2010 12:45:26 GMT

- Location
用来重定向接收方到非请求URL的位置来完成请求或标识新的资源
Location: http://www.agesec.com/5210.html

- Pragma
包括实现特定的指令，它可应用到响应链上的任何接收方
Pragma: no-cache

- Proxy-Authenticate
它指出认证方案和可应用到代理的该URL上的参数
Proxy-Authenticate: Basic

- Refresh
应用于重定向或一个新的资源被创造，在5秒之后重定向（由网景提出，被大部分浏览器支持）
Refresh: 5; url=http://www.agesec.com/5210.html

- Retry-After
如果实体暂时不可取，通知客户端在指定时间之后再次尝试
Retry-After: 120

- Server web
服务器软件名称
Server: Apache/1.3.27 (Unix) (Red-Hat/Linux)

- Set-Cookie
设置Http Cookie Set-Cookie: UserID=JohnDoe; Max-Age=3600; Version=1

- Trailer
指出头域在分块传输编码的尾部存在 Trailer: Max-Forwards

- Transfer-Encoding
文件传输编码
Transfer-Encoding:chunked

- Vary
告诉下游代理是使用缓存响应还是从原始服务器请求
Vary: *

- Via
告知代理客户端响应是通过哪里发送的
Via: 1.0 fred, 1.1 nowhere.com (Apache/1.1)

- Warning
警告实体可能存在的问题
Warning: 199 Miscellaneous warning

- WWW-Authenticate
表明客户端请求实体应该使用的授权方案
WWW-Authenticate: Basic


------------

1.4.4. HTTP状态返回代码 1xx（临时响应）
表示临时响应并需要请求者继续执行操作的状态代码。

![s](https://note.youdao.com/yws/public/resource/2e5cf2591c66904f78df39f912277f6d/xmlnote/WEBRESOURCE06762fa135d0dc3167a0609783f7e3f5/8754 "s")

1.4.5. HTTP状态返回代码 2xx （成功
表示成功处理了请求的状态代码。
![s](https://note.youdao.com/yws/public/resource/2e5cf2591c66904f78df39f912277f6d/xmlnote/WEBRESOURCEc1a7253094877352d182e48d2cc951e3/8756 "s")

1.4.6. HTTP状态返回代码 3xx （重定向）
表示要完成请求，需要进一步操作。通常，这些状态代码用来重定向。
![s](https://note.youdao.com/yws/public/resource/2e5cf2591c66904f78df39f912277f6d/xmlnote/WEBRESOURCEc0c10046a9f416b15d40aec7988069dc/8759 "s")

1.4.7. HTTP状态返回代码 4xx（请求错误）
这些状态代码表示请求可能出错，妨碍了服务器的处理。
![s](https://note.youdao.com/yws/public/resource/2e5cf2591c66904f78df39f912277f6d/xmlnote/WEBRESOURCE92be93f4cf3202545d40f2fd77bc55c6/8758 "s")

1.4.8. HTTP状态返回代码 5xx（服务器错误）
这些状态代码表示服务器在尝试处理请求时发生内部错误。这些错误可能是服务器本身的错误，而不是请求出错。

![s](https://note.youdao.com/yws/public/resource/2e5cf2591c66904f78df39f912277f6d/xmlnote/WEBRESOURCE518f3324c52e8587ad4cead7a7c53fae/8767 "s")