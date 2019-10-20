# WEB安全渗透测试基础知识（十四）

**JavaScript**

4.4.1. 原型链

4.4.1.1. 显式原型和隐式原型

JavaScript的原型分为显式原型（explicit prototype property）和隐式原型（implicit prototype link）。  
其中显式原型指prototype，是函数的一个属性，这个属性是一个指针，指向一个对象，显示修改对象的原型的属性，只有函数才有该属性。  

隐式原型指JavaScript中任意对象都有的内置属性prototype。在ES5之前没有标准的方法访问这个内置属性，但是大多数浏览器都支持通过 __proto__ 来访问。ES5中有了对于这个内置属性标准的Get方法 Object.getPrototypeOf() 。  

隐式原型指向创建这个对象的函数(constructor)的prototype， __proto__

指向的是当前对象的原型对象，而prototype指向的，是以当前函数作为构造函数构造出来的对象的原型对象。  
显式原型的作用用来实现基于原型的继承与属性的共享。隐式原型的用于构成原型链，同样用于实现基于原型的继承。举个例子，当我们访问obj这个对象中的x属性时，如果在obj中找不到，那么就会沿着 __proto__ 依次查找。  
Note: Object.prototype 这个对象是个例外，它的__proto__值为null


4.4.1.2. new 的过程


```
var Person = function(){}; 
var p = new Person();
```

new的过程拆分成以下三步：– var p={}; 初始化一个对象p – p.__proto__ = Person.prototype; – Person.call(p); 构造p，也可以称之为初始化p  

关键在于第二步，我们来证明一下：  


```
var Person = function(){}; 
var p = new Person(); 
alert(p.__proto__ === Person.prototype);
```

这段代码会返回true。说明我们步骤2是正确的。

4.4.1.3. 示例
![image](https://note.youdao.com/yws/public/resource/2e5cf2591c66904f78df39f912277f6d/xmlnote/WEBRESOURCEa8f8cf2b48f4d086cb25afb22da23d96/9478)

p是一个引用指向Person的对象。我们在Person的原型上定义了一个sayName方法和age属性，当我们执行p.age时，会先在this的内部查找（也就是构造函数内部），如果没有找到然后再沿着原型链向上追溯。  
这里的向上追溯是怎么向上的呢？这里就要使用 __proto__ 属性来链接到原型（也就是Person.prototype）进行查找。最终在原型上找到了age属性。

---
4.4.2. 沙箱逃逸
![image](https://note.youdao.com/yws/public/resource/2e5cf2591c66904f78df39f912277f6d/xmlnote/WEBRESOURCE170a6e9f86ceb38882e25573e869cc56/9479)


---
4.4.3. 反序列化

4.4.3.1. 简介

JavaScript本身并没有反序列化的实现，但是一些库如node-serialize、serialize-to-js等支持了反序列化功能。这些库通常使用JSON形式来存储数据，但是和原生函数JSON.parse、 JSON.stringify不同，这些库支持任何对象的反序列化，特别是函数，如果使用不当，则可能会出现反序列化问题。

4.4.3.2. Payload构造

下面是一个最简单的例子，首先获得序列化后的输出
![image](https://note.youdao.com/yws/public/resource/d7012273fa21e7de46c1d6e7de7a7619/xmlnote/C8E921BCF13C49DC837D997C6EA1E91C/9500)
上面执行后会返回
![image](https://note.youdao.com/yws/public/resource/d7012273fa21e7de46c1d6e7de7a7619/xmlnote/874F863DE5684A93B6EA9926C46D943D/9495)

不过这段payload反序列化后并不会执行，但是在JS中支持立即调用的函数表达式（Immediately Invoked Function Expression），比如 (function () { /* code */ } ()); 这样就会执行函数中的代码。那么可以使用这种方法修改序列化后的字符串来完成一次反序列化。最后的payload测试如下:

![image](https://note.youdao.com/yws/public/resource/2e5cf2591c66904f78df39f912277f6d/xmlnote/WEBRESOURCEcefa6913bedfc715a48044153d92c48d/9522)

4.4.3.3. Payload构造 II

以上提到的是node-serialize这类反序列化库的构造方式，还有一类库如funcster，是使用直接拼接字符串构造函数的方式来执行。
![image](https://note.youdao.com/yws/public/resource/2e5cf2591c66904f78df39f912277f6d/xmlnote/WEBRESOURCEdde50ba430638be37b2d45d60d379b48/9514)

这种方式可以使用相应的闭合来构造payload。

---
4.4.4. 其他

4.4.4.1. 命令执行

Node.js中child_process.exec命令调用的是/bin/sh，故可以直接使用该命令执行shell

4.4.4.2. 反调试技巧

- 函数重定义 console.log = function(a){}
- 定时断点 setInterval(function(){debugger}, 1000);

