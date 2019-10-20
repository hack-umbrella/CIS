# WEB安全渗透测试基础知识（十八）


**入侵检测**

6.7.1. 常见入侵点
- Web入侵
- 高危服务入侵


---
6.7.2. 常见实现

6.7.2.1. 客户端监控

- 监控敏感配置文件
- 常用命令ELF文件完整性监控
ps
lsof
…
- rootkit监控
- 资源使用报警
内存使用率
CPU使用率
IO使用率
网络使用率
- 新出现进程监控
- 基于inotify的文件监控

6.7.2.2. 网络检测

基于网络层面的攻击向量做检测，如Snort等。
6.7.2.3. 日志分析

将主机系统安全日志/操作日志、网络设备流量日志、Web应用访问日志、SQL应用访问日志等日志集中到一个统一的后台，在后台中对各类日志进行综合的分析。


---
**应急响应**

6.8.1. 响应流程

6.8.1.1. 事件发生

运维监控人员、客服审核人员等发现问题，向上通报
6.8.1.2. 事件确认

判断事件的严重性，评估出问题的严重等级，是否向上进行汇报等
6.8.1.3. 事件响应

各部门通力合作，处理安全问题，具体解决阶段
6.8.1.4. 事件关闭

处理完事件之后，需要关闭事件，并写出安全应急处理分析报告，完成整个应急过程。


---
6.8.2. 事件分类

- 病毒、木马、蠕虫事件
- Web服务器入侵事件
- 第三方服务入侵事件
- 系统入侵事件
利用Windows漏洞攻击操作系统
- 网络攻击事件
DDoS / ARP欺骗 / DNS劫持等

---
6.8.3. 分析方向

6.8.3.1. 文件分析
- 基于变化的分析
日期
文件增改
最近使用文件
- 源码分析
检查源码改动
查杀WebShell等后门
- 系统日志分析
- 应用日志分析
分析User-Agent，e.g. awvs / burpsuite / w3af / nessus / openvas
对每种攻击进行关键字匹配，e.g. select/alert/eval
异常请求，连续的404或者500
- md5sum 检查常用命令二进制文件的哈希，检查是否被植入rootkit

6.8.3.2. 进程分析
- 符合以下特征的进程
CPU或内存资源占用长时间过高
没有签名验证信息
没有描述信息的进程
进程的路径不合法
- dump系统内存进行分析

6.8.3.3. 网络分析
- 防火墙配置
- DNS配置
- 路由配置

6.8.3.4. 配置分析
- 查看Linux SE等配置
- 查看环境变量
- 查看配套的注册表信息检索，SAM文件
- 内核模块


---
6.8.4. Linux应急响应

6.8.4.1. 文件分析
- 最近使用文件
find / -ctime -2
C:\Documents and Settings\Administrator\Recent
C:\Documents and Settings\Default User\Recent
%UserProfile%\Recent
- 系统日志分析
/var/log/
- 重点分析位置

```
/var/log/wtmp登录进入，退出，数据交换、关机和重启纪录
/var/run/utmp 有关当前登录用户的信息记录
/var/log/lastlog 文件记录用户最后登录的信息，可用 lastlog 命令来查看。
/var/log/secure 记录登入系统存取数据的文件，例如 pop3/ssh/telnet/ftp 等都会被记录。
/var/log/cron 与定时任务相关的日志信息
/var/log/message 系统启动后的信息和错误日志
/var/log/apache2/access.log
apache access log
/etc/passwd 用户列表
/etc/init.d/ 开机启动项
/etc/cron* 定时任务
/tmp 临时目录
~/.ssh
```

6.8.4.2. 用户分析
- /etc/shadow 密码登陆相关信息
- uptime 查看用户登陆时间
- /etc/sudoers sudo用户列表

6.8.4.3. 进程分析
- netstat -ano 查看是否打开了可疑端口
- w 命令，查看用户及其进程
- 分析开机自启程序/脚本
/etc/init.d
~/.bashrc
- 查看计划或定时任务
crontab -l
- netstat -an / lsof 查看进程端口占用

---
6.8.5. Windows应急响应

6.8.5.1. 文件分析
- 最近使用文件

C:\Documents and Settings\Administrator\Recent

C:\Documents and Settings\Default User\Recent
%UserProfile%\Recent
- 系统日志分析

事件查看器 eventvwr.msc

6.8.5.2. 用户分析
- 查看是否有新增用户
- 查看服务器是否有弱口令
- 查看管理员对应键值
- lusrmgr.msc 查看账户变化
- net user 列出当前登录账户
- wmic UserAccount get 列出当前系统所有账户

6.8.5.3. 进程分析
- netstat -ano 查看是否打开了可疑端口
- tasklist 查看是否有可疑进程
- 分析开机自启程序

```
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Runonce HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\policies\Explorer\Run HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce
(ProfilePath)\Start Menu\Programs\Startup 启动项
msconfig 启动选项卡
gpedit.msc 组策略编辑器
```

- 查看计划或定时任务

C:\Windows\System32\Tasks\

C:\Windows\SysWOW64\Tasks\

C:\Windows\tasks\

schtasks

taskschd.msc
