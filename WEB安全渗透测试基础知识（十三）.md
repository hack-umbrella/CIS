# WEB安全渗透测试基础知识（十三）

**Python**

4.2.1. 格式化字符串
在Python中，有两种格式化字符串的方式，在Python2的较低版本中，格式化字符串的方式为 "this is a %s" % "test" ，之后增加了format的方式， 语法为 "this is a {}".format('test') 或者 "this is a {test}".format(test='test')

当格式化字符串由用户输入时，则可能会造成一些问题，下面是一个最简单的例子


```
>>> 'class of {0} is {0.__class__}'.format(42) 
"class of 42 is <class 'int'>"
```


从上面这个简单的例子不难知道，当我们可以控制要format的字符串时，则可以使用 __init__ / __globals__ 等属性读取一些比较敏感的值，甚至任意执行代码。

---
4.2.2. 反序列化

4.2.2.1. pickle


```
>>> class A(object): 
...         a = 1 
...         b = 2 
...       def __reduce__(self): 
...   return (subprocess.Popen, (('cmd.exe',),)) 
... 
>>>   cPickle.dumps(A()) 
"csubprocess\nPopen\np1\n((S'cmd.exe'\np2\ntp3\ntp4\nRp5\n."
```


4.2.2.2. 其他
- PyYAML
- marshal
- shelve


---
4.2.3. 沙箱

4.2.3.1. 常用函数
- eval / exec / compile
- dir / type
- globals / locals / vars
- getattr / setattr

4.2.3.2. 绕过

最简单的思路是在已有的模块中import，如果那个模块中已经 import 可以利用的模块就可以使用了
在父类中寻找可用的模块，最常见payload是 
```
().__class__.__bases__[0].__subclasses__() 或者用魔术方法获取全局作用域 __init__.__func__.__globals__
```


有些网站没有过滤 pickle 模块，可以使用 pickle 实现任意代码执行，生成 payload 可以使用 https://gist.github.com/freddyb/3360650
有的沙箱把相关的模块代码都被删除了，则可以使用libc中的函数，Python 中调用一般可以使用 ctypes 或者 cffi。

"A""B" == "AB"

4.2.3.3. 防御

- Python官方给出了一些防御的建议  
- 使用Jython并尝试使用Java平台来锁定程序的权限
- 使用fakeroot来避免
- 使用一些rootjail的技术

---
4.2.4. 框架

4.2.4.1. Django

4.2.4.1.1. 历史漏洞
- CVE-2016-7401 CSRF Bypass
- CVE-2017-7233/7234 Open redirect vulnerability
- CVE-2017-12794 debug page XSS

4.2.4.1.2. 配置相关

- Nginx 在为 Django 做反向代理时，静态文件目录配置错误会导致源码泄露。访问 /static.. 会 301 重定向到 /static../

4.2.4.2. Flask

Flask默认使用客户端session，使得session可以被伪造


---
4.2.5. 危险函数 / 模块列表

4.2.5.1. 命令执行


```
os.popen
os.system
os.spawn
os.fork
os.exec
popen2
commands
subprocess
exec
execfile
eval
timeit.sys
timeit.timeit
platform.os
platform.sys
platform.
popen
pty.spawn
pty.os
bdb.os
cgi.sys
…
```
4.2.5.2. 危险第三方库
- Template
- subprocess32

4.2.5.3. 反序列化
- marshal
- PyYAML
- pickle
- cPickle
- shelve
- PIL

---
**Java*
4.3.1. 基本概念

JVM是Java平台的核心，以机器代码来实现，为程序执行提供了所需的所有基本功能，例如字节码解析器、JIT编译器、垃圾收集器等。由于它是机器代码实现的，其同样受到二进制文件受到的攻击。  

JCL是JVM自带的一个标准库，含有数百个系统类。默认情况下，所有系统类都是可信任的，且拥有所有的特权。

4.3.1.2. JNDI

JNDI（Java Naming and Directory Interface，JAVA命名和目录接口）是为JAVA应用程序提供命名和目录访问服务的API（Application Programing Interface，应用程序编程接口）。

4.3.1.3. OGNL

OGNL（Object-Graph Navigation Language，对象导航语言）是一种功能强大的表达式语言，通过简单一致的表达式语法，提供了存取对象的任意属性、调用对象的方法、遍历整个对象的结构图、实现字段类型转化等功能。  

Struts2中使用了OGNL，提供了一个ValueStack类。ValueStack分为root和context两部分。root中是当前的action对象，context中是ActionContext里面所有的内容。

4.3.1.4. RMI

RMI（Remote Method Invocation，远程方法调用）能够让在客户端Java虚拟机上的对象像调用本地对象一样调用服务端java虚拟机中的对象上的方法。  

RMI远程调用步骤：  
- 客户调用客户端辅助对象stub上的方法
- - 客户端辅助对象stub打包调用信息（变量，方法名），通过网络发送给服务端辅助对象skeleton
- 服务端辅助对象skeleton将客户端辅助对象发送来的信息解包，找出真正被调用的方法以及该方法所在对象
- 调用真正服务对象上的真正方法，并将结果返回给服务端辅助对象skeleton
- 服务端辅助对象将结果打包，发送给客户端辅助对象stub
- 客户端辅助对象将返回值解包，返回给调用者
- 客户获得返回值

---
4.3.2. 框架

4.3.2.1. Servlet

4.3.2.1.1. 简介

Servlet（Server Applet）是Java Servlet的简称，称为小服务程序或服务连接器，是用Java编写的服务器端程序，主要功能在于交互式地浏览和修改数据，生成动态Web内容。  

狭义的Servlet是指Java语言实现的一个接口，广义的Servlet是指任何实现了这个Servlet接口的类，一般情况下，人们将Servlet理解为后者。Servlet运行于支持Java的应用服务器中。从原理上讲，Servlet可以响应任何类型的请求，但绝大多数情况下Servlet只用来扩展基于HTTP协议的Web服务器。

4.3.2.1.2. 生命周期为
- 客户端请求该 Servlet
- 加载 Servlet 类到内存
- 实例化并调用init()方法初始化该
- Servlet service()（根据请求方法不同调用 doGet() / doPost() / … / destroy()

4.3.2.1.3. 接口

init()  

在 Servlet 的生命期中，仅执行一次 init() 方法，在服务器装入 Servlet 时执行。  

service()  

service() 方法是 Servlet
的核心。每当一个客户请求一个HttpServlet对象，该对象的 service() 方法就要被调用，而且传递给这个方法一个”请求”(ServletRequest)对象和一个”响应”(ServletResponse)对象作为参数。

4.3.2.2. Struts 2

4.3.2.2.1. 简介

Struts2是一个基于MVC设计模式的Web应用框架，它本质上相当于一个servlet，在MVC设计模式中，Struts2作为控制器(Controller)来建立模型与视图的数据交互。

4.3.2.2.2. 请求流程

```
客户端发送请求的tomcat服务器
请求经过一系列过滤器
FilterDispatcher调用ActionMapper来决定这个请求是否要调用某个Action
ActionMppaer决定调用某个ActionFilterDispatcher把请求给ActionProxy
ActionProxy通过Configuration Manager查看structs.xml，找到对应的Action类
ActionProxy创建一个ActionInvocation对象
ActionInvocation对象回调Action的execute方法
Action执行完毕后，ActionInvocation根据返回的字符串，找到相应的result，通过HttpServletResponse返回给服务器
```

4.3.2.2.3. 相关CVE

```
CVE-2016-3081 (S2-032)
CVE-2016-3687 (S2-033)
CVE-2016-4438 (S2-037)
CVE-2017-5638
CVE-2017-7672
CVE-2017-9787
CVE-2017-9793
CVE-2017-9804
CVE-2017-9805
CVE-2017-12611
CVE-2017-15707
CVE-2018-1327
CVE-2018-11776
```

4.3.2.3. Spring MVC

4.3.2.3.1. 请求流程


```
用户发送请求给服务器
服务器收到请求，使用DispatchServlet处理
Dispatch使用HandleMapping检查url是否有对应的Controller，如果有，执行
如果Controller返回字符串，ViewResolver将字符串转换成相应的视图对象
DispatchServlet将视图对象中的数据，输出给服务器 服务器将
数据输出给客户端
```

---
4.3.3. 容器

常见的Java服务器有Tomcat、Weblogic、JBoss、GlassFish、Jetty、Resin、IBM Websphere等，这里对部分框架做一个简单的说明。

4.3.3.1. Tomcat
Tomcat是一个轻量级应用服务器，在中小型系统和并发访问用户不是很多的场合下被普遍使用，用于开发和调试JSP程序。  
在收到请求后，Tomcat的处理流程如下：  

```
客户端访问Web服务器，发送HTTP请求
Web服务器接收到请求后，传递给Servlet容器
Servlet容器加载Servlet，产生Servlet实例后，向其传递表示请求和响应的对象
Servlet实例使用请求对象得到客户端的请求信息，然后进行相应的处理
Servlet实例将处理结果通过响应对象发送回客户端，容器负责确保响应正确送出，同时将控制返回给Web服务器 
Tomcat服务器是由一系列可配置的组件构成的，其中核心组件是Catalina Servlet容器，它是所有其他Tomcat组件的顶层容器。
```

4.3.3.1.1. 相关CVE


```
CVE-2019-0232
https://github.com/pyn3rd/CVE-2019-0232/
CVE-2017-12615
https://mp.weixin.qq.com/s?__biz=MzI1NDg4MTIxMw==&mid=2247483659&idx=1&sn=c23b3a3b3b43d70999bdbe644e79f7e5
CVE-2013-2067
CVE-2012-4534
CVE-2012-4431
CVE-2012-3546
CVE-2012-3544
CVE-2012-2733
CVE-2011-3375
CVE-2011-3190
CVE-2008-2938
```

4.3.3.2. Weblogic

4.3.3.2.1. 简介

WebLogic是美国Oracle公司出品的一个Application Server，是一个基于Java EE架构的中间件，WebLogic是用于开发、集成、部署和管理大型分布式Web应用、网络应用和数据库应用的Java应用服务器。其将Java的动态功能和Java Enterprise标准的安全性引入大型网络应用的开发、集成、部署和管理之中。  

WebLogic对业内多种标准的全面支持，包括EJB、JSP、Servlet、JMS、JDBC等。

4.3.3.2.2. 相关CVE

```
CVE-2019-2658
CVE-2019-2650
CVE-2019-2649
CVE-2019-2648
CVE-2019-2647
CVE-2019-2646
CVE-2019-2645
CVE-2019-2618
https://github.com/jas502n/cve-2019-2618/
CVE-2019-2615
CVE-2019-2568
CVE-2018-3252
CVE-2018-3248
CVE-2018-3245
CVE-2018-3201
CVE-2018-3197
CVE-2018-3191
https://github.com/voidfyoo/CVE-2018-3191
https://github.com/Libraggbond/CVE-2018-3191
CVE-2018-2894
https://xz.aliyun.com/t/2458
CVE-2018-2628 https://mp.weixin.qq.com/s/nYY4zg2m2xsqT0GXa9pMGA
CVE-2018-1258
CVE-2017-10271
http://webcache.googleusercontent.com/search?q=cache%3AsH7j8TF8uOIJ%3Awww.freebuf.com%2Fvuls%2F160367.html
CVE-2017-3248
CVE-2016-3510
CVE-2015-4852
https://github.com/roo7break/serialator
```

4.3.3.3. JBoss

4.3.3.3.1. 简介

JBoss是一个基于J2EE的管理EJB的容器和服务器，但JBoss核心服务不包括支持servlet/JSP的WEB容器，一般与Tomcat或Jetty绑定使用。

4.3.3.3.2. 相关CVE


```
CVE-2017-12149
```

---
4.3.4. 沙箱

4.3.4.1. 简介

Java实现了一套沙箱环境，使远程的非可信代码只能在受限的环境下执行。

4.3.4.2. 相关CVE

```
CVE-2012-0507
CVE-2012-4681
CVE-2017-3272
CVE-2017-3289
```
4.3.5. 反序列化

4.3.5.1. 简介

序列化就是把对象转换成字节流，便于保存在内存、文件、数据库中；反序列化即逆过程，由字节流还原成对象。Java中的 ObjectOutputStream 类的 writeObject() 方法可以实现序列化，类 ObjectInputStream类的readObject() 方法用于反序列化。  

如果要实现类的反序列化，则是对其实现 Serializable 接口。

4.3.5.2. 序列数据结构

0xaced 魔术头

4.3.5.3. 序列化流程


```
ObjectOutputStream实例初始化时，将魔术头和版本号写入bout （BlockDataOutputStream类型） 中
调用ObjectOutputStream.writeObject()开始写对象数据
○ObjectStreamClass.lookup()封装待序列化的类描述 （返回ObjectStreamClass类型） ，获取包括类名、自定义serialVersionUID、可序列化字段 （返回ObjectStreamField类型） 和构造方法，以及writeObject、readObject方法等
○writeOrdinaryObject()写入对象数据
■写入对象类型标识
■writeClassDesc()进入分支writeNonProxyDesc()写入类描述数据
写入类描述符标识
写入类名
写入SUID （当SUID为空时，会进行计算并赋值）
计算并写入序列化属性标志位
写入字段信息数据
写入Block Data结束标识
写入父类描述数据
■writeSerialData()写入对象的序列化数据
若类自定义了writeObject()，则调用该方法写对象，否则调用defaultWriteFields()写入对象的字段数据 （若是非原始类型，则递归处理子对象）
```

4.3.5.4. 反序列化流程


```
ObjectInputStream实例初始化时，读取魔术头和版本号进行校验
调用ObjectInputStream.readObject()开始读对象数据
○读取对象类型标识
○readOrdinaryObject()读取数据对象
■readClassDesc()读取类描述数据
读取类描述符标识，进入分支readNonProxyDesc()
读取类名
读取SUID
读取并分解序列化属性标志位
读取字段信息数据
resolveClass()根据类名获取待反序列化的类的Class对象，如果获取失败，则抛出ClassNotFoundException
skipCustomData()循环读取字节直到Block Data结束标识为止 读取父类描述数据
initNonProxy()中判断对象与本地对象的SUID和类名 （不含包名） 是否相同，若不同，则抛出InvalidClassException
ObjectStreamClass.newInstance()获取并调用离对象最近的非■Serializable的父类的无参构造方法 （若不存在，则返回null） 创建对象实例
■readSerialData()读取对象的序列化数据
若类自定义了readObject()，则调用该方法读对象，否则调用defaultReadFields()读取并填充对象的字段数据
```

4.3.5.5. 相关函数


```
ObjectInputStream.readObject
ObjectInputStream.readUnshared
XMLDecoder.readObject
Yaml.load
XStream.fromXML
ObjectMapper.readValue
JSON.parseObject
```

4.3.5.6. 主流JSON库

4.3.5.6.1. GSON

Gson默认只能反序列化基本类型，如果是复杂类型，需要程序员实现反序列化机制，相对比较安全。

4.3.5.6.2. Jackson

除非指明@jsonAutoDetect，Jackson不会反序列化非public属性。在防御时，可以不使用enableDefaultTyping方法。  

相关CVE有  

```
CVE-2017-7525
CVE-2017-15095
```

4.3.5.6.3. Fastjson

相关CVE有  

CVE-2017-18349

4.3.5.7. 存在危险的基础库

```
commons-fileupload 1.3.1
commons-io 2.4
commons-collections 3.1
commons-logging 1.2
commons-beanutils 1.9.2
org.slf4j:slf4j-api 1.7.21
com.mchange:mchange-commons-java 0.2.11
org.apache.commons:commons-collections 4.0
com.mchange:c3p0 0.9.5.2
org.beanshell:bsh 2.0b5
org.codehaus.groovy:groovy 2.3.9
org.springframework:spring-aop 4.1.4.RELEASE
```

4.3.5.8. 漏洞修复和防护

4.3.5.8.1. Hook resolveClass

在使用 readObject() 反序列化时会调用 resolveClass 方法读取反序列化的类名，可以通过hook该方法来校验反序列化的类，一个Demo如下

![image](https://note.youdao.com/yws/public/resource/2e5cf2591c66904f78df39f912277f6d/xmlnote/WEBRESOURCE217ed0022320aed798ece9390b3c765d/9458)

以上的Demo就只允许序列化 SerialObject ，通过这种方式，就可以设置允许序列化的白名单

4.3.5.8.2. ValidatingObjectInputStream

Apache Commons IO Serialization包中的 ValidatingObjectInputStream 类提供了 accept 方法，可以通过该方法来实现反序列化类白/黑名单控制，一个demo如下

![image](https://note.youdao.com/yws/public/resource/2e5cf2591c66904f78df39f912277f6d/xmlnote/WEBRESOURCE1396664adda60a6eab70eba12353ce80/9459)

4.3.5.8.3. ObjectInputFilter

Java 9提供了支持序列化数据过滤的新特性，可以继承 java.io.ObjectInputFilter 类重写 checkInput方法来实现自定义的过滤器，并使用 ObjectInputStream 对象的 setObjectInputFilter 设置过滤器来实现反序列化类白/黑名单控制。