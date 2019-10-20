# WEB安全渗透测试基础知识（十五）


**Windows系统持久化**

5.2. 持久化 – Windows

5.2.1. 隐藏文件

- 创建系统隐藏文件
attrib +s +a +r +h filename / attrib +s +h filename
- 利用NTFS ADS (Alternate　Data　Streams) 创建隐藏文件
- 利用Windows保留字
aux|prn|con|nul|com1|com2|com3|com4|com5|com6|com7|com8|com9|lpt1|lpt2|lpt3|lpt4|lpt5|lpt6|lpt7|lpt8|lpt9


---
5.2.2. UAC

5.2.2.1. 简介

UAC (User Account Control) 是Windows的一个安全机制，当一些敏感操作发生时，会跳出提示显式要求系统权限。  

当用户登陆Windows时，每个用户都会被授予一个access token，这个token中有security identifier (SID) 的信息，决定了用户的权限。

5.2.2.2. 会触发UAC的操作

```
以管理员权限启动应用
修改系统、UAC设置
修改没有权限的文件或者目录（ %SystemRoot% / %ProgramFiles% 等 ）
修改ACL (access control list) 安装驱动
增删账户，修改账户类型，激活来宾账户
```

---
5.2.3. 权限提升

权限提升有多重方式，有利用二进制漏洞、逻辑漏洞等技巧。利用二进制漏洞获取权限的方式是利用运行在内核态中的漏洞来执行代码。比如内核、驱动中的UAF或者其他类似的漏洞，以获得较高的权限。

逻辑漏洞主要是利用系统的一些逻辑存在问题的机制，比如有些文件夹用户可以写入，但是会以管理员权限启动。

5.2.3.1. 任意写文件利用

在Windows中用户可以写的敏感位置主要有以下这些
- 用户自身的文件和目录，包括 AppData Temp
- C:\ ，默认情况下用户可以写入
- C:\ProgramData 的子目录，默认情况下用户可以创建文件夹、写入文件
- C:\Windows\Temp 的子目录，默认情况下用户可以创建文件夹、写入文件

具体的ACL信息可用AccessChk, 或者PowerShell的 Get-Acl 命令查看。  
可以利用对这些文件夹及其子目录的写权限，写入一些可能会被加载的dll，利用dll的加载执行来获取权限。

5.2.3.2. MOF
MOF是Windows系统的一个文件（ c:/windows/system32/wbem/mof/nullevt.mof ）叫做”托管对象格式”，其作用是每隔五秒就会去监控进程创建和死亡。  

当拥有文件上传的权限但是没有Shell时，可以上传定制的mof文件至相应的位置，一定时间后这个mof就会被执行。 
 一般会采用在mof中加入一段添加管理员用户的命令的vbs脚本，当执行后就拥有了新的管理员账户。
 
5.2.3.3. sethc

sethc.exe 是 Windows系统在用户按下五次shift后调用的粘滞键处理程序，当有写文件但是没有执行权限时，可以通过替换 sethc.exe 的方式留下后门，在密码输入页面输入五次shift即可获得权限。

5.2.3.4. 凭证窃取

```
Windows本地密码散列导出工具
mimikatz
wce
gsecdump
copypwd
Pwdump
Windows本地密码破解工具
L0phtCrack
SAMInside
Ophcrack
彩虹表破解
本机hash+明文抓取
win8+win2012明文抓取
ntds.dit的导出+QuarkPwDump读取分析
vssown.vbs + libesedb + NtdsXtract
ntdsdump
利用powershell(DSInternals)分析hash
使用 net use \\%computername% /u:%username% 重置密码尝试次数
```

5.2.3.5. 其他

- 组策略首选项漏洞
- DLL劫持
- 替换系统工具，实现后门


---
**Linux信息收集**

5.3. 信息收集 – Linux

5.3.1. 获取内核，操作系统和设备信息

- 版本信息
uname -a 所有版本
uname -r 内核版本信息
uname -n 系统主机名字
uname -m Linux
- 内核架构 内核信息 cat /proc/version
- CPU信息 cat /proc/cpuinfo
- 发布信息

cat /etc/*-release

cat /etc/issue

主机名 hostname

文件系统 df -a


---
5.3.2. 用户和组

```
列出系统所有用户 cat /etc/passwd
列出系统所有组 cat /etc/group
列出所有用户hash（root）“cat /etc/shadow“
用户
查询用户的基本信息 finger
当前登录的用户 users who -a
目前登录的用户 w
登入过的用户信息 last
显示系统中所有用户最近一次登录信息 lastlog
```
5.3.3. 用户和权限信息
- 当前用户 whoami
- 当前用户信息 id
- 可以使用sudo提升到root的用户（root） cat /etc/sudoers
- 列出目前用户可执行与无法执行的指令 sudo -l

---

5.3.4. 环境信息

```
打印系统环境信息 env
打印系统环境信息 set
环境变量中的路径信息 echo  $PATH
打印历史命令 history
显示当前路径 pwd
显示默认系统遍历 cat /etc/profile
显示可用的shell cat /etc/shells
```

---
5.3.5. 服务信息
- 查看进程信息 ps aux
- 由inetd管理的服务列表 cat /etc/inetd.conf
- 由xinetd管理的服务列表 cat /etc/xinetd.conf
- nfs服务器的配置 cat /etc/exports

---
5.3.6. 作业和任务
- 显示指定用户的计划作业（root） crontab -l -u %user%
- 计划任务 ls -la /etc/cron*

---
5.3.7. 网络、路由和通信

```
列出网络接口信息 /sbin/ifconfig -a
列出网络接口信息 cat /etc/network/interfaces
查看系统arp表 arp -a
打印路由信息 route
查看dns配置信息 cat /etc/resolv.conf
打印本地端口开放信息 netstat -an
列出iptable的配置规则 iptables -L
查看端口服务映射 cat /etc/services
```

---
**入侵痕迹清理**

5.4. 入侵痕迹清理

5.4.1. Windows
- 操作日志：3389登录列表、文件访问日志、浏览器日志、系统事件
- 登录日志：系统安全日志

---
5.4.2. Linux

- 清除历史
unset HISTORY HISTFILE HISTSAVE HISTZONE HISTORY HISTLOG; export HISTFILE=/dev/null;
- 删除 ~/.ssh/known_hosts 中记录
- 修改文件时间戳
touch –r
- 删除tmp目录临时文件


---
5.4.3. 难点
- 攻击和入侵很难完全删除痕迹，没有日志记录也是一种特征
- 即使删除本地日志，在网络设备、安全设备、集中化日志系统中仍有记录
- 留存的后门包含攻击者的信息
- 使用的代理或跳板可能会被反向入侵

---
5.4.4. 注意
- 在操作前检查是否有用户在线
- 删除文件使用磁盘覆写的功能删除
- 尽量和攻击前状态保持一致
