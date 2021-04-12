---
title: 面试——其他篇
date: 2020-12-29 10:23:51
tags: 
  - 面试
  - js
type: 面试                                                                 # 标签、分类
description:  JavaScript（简称“JS”） 是一种具有函数优先的轻量级，解释型或即时编译型的编程语言。
top_img: https://ss3.bdstatic.com/70cFv8Sh_Q1YnxGkpoWK1HF6hhy/it/u=955487690,3458128037&fm=26&gp=0.jpg             # 文章的顶部图片
aside: true                                                                         # 展示文章侧边栏(默认为true)
categories: 
  - 面试
  - js                                                                 # 文章标签
cover: https://ss3.bdstatic.com/70cFv8Sh_Q1YnxGkpoWK1HF6hhy/it/u=955487690,3458128037&fm=26&gp=0.jpg                 # 文章的缩略图（用在首页）
---

# 询问工作经历，在项目中如何做性能优化的？
  1. content方面
    * 减少HTTP请求：合并文件、CSS精灵、inline Image
    * 减少DNS查询：DNS查询完成之前浏览器不能从这个主机下载任何任何文件。方法：DNS缓存、将资源分布到恰当数量的主机名，平衡并行下载和DNS查询
    * 避免重定向：多余的中间访问
    * 使Ajax可缓存
    * 非必须组件延迟加载
    * 未来所需组件预加载
    * 减少DOM元素数量
    * 将资源放到不同的域下：浏览器同时从一个域下载资源的数目有限，增加域可以提高并行下载量
    * 减少iframe数量
    * 不要404

  2. Server方面
    * 使用CDN
    * 添加Expires或者Cache-Control响应头
    * 对组件使用Gzip压缩
    * 配置ETag
    * Flush Buffer Early
    * Ajax使用GET进行请求
    * 避免空src的img标签

  3. Cookie方面
    * 减小cookie大小
    * 引入资源的域名不要包含cookie

  4. css方面
    * 将样式表放到页面顶部
    * 不使用CSS表达式
    * 使用不使用@import
    * 不使用IE的Filter

  5. Javascript方面
    * 将脚本放到页面底部
    * 将javascript和css从外部引入
    * 压缩javascript和css
    * 删除不需要的脚本

  6. 图片方面
    * 优化图片：根据实际颜色需要选择色深、压缩
    * 优化css精灵
    * 不要在HTML中拉伸图片
    * 保证favicon.ico小并且可缓存
---

# 组件库如何做按需加载
---

# 你认为自己做的项目有什么值得的说道的地方吗？这里其实就是考察项目的亮点，可以说一些项目难点是如何解决的，或者介绍一些项目中用到的比较高级的技术。
---

# 常使用的库有哪些？常用的前端开发工具？开发过什么应用或组件？
---

# 除了前端以外还了解什么其它技术么？你最最厉害的技能是什么？
---

# 如何管理前端团队?
---

# 你在现在的团队处于什么样的角色，起到了什么明显的作用？
---

# 最近在学什么？能谈谈你未来3，5年给自己的规划吗？
---

# 简单描述一下你做过的移动APP项目研发流程？
---

# 你对加班的看法？
---

# 你的优点是什么？缺点是什么？
---

# 权限组件是怎么设计的
---

# 自己有什么技术上的优势
---

# 职业规划
---

# 平时如何管理你的项目？
  1. 先期团队必须确定好全局样式（globe.css），编码模式(utf-8) 等；
  2. 编写习惯必须一致（例如都是采用继承式的写法，单样式都写成一行）；
  3. 标注样式编写人，各模块都及时标注（标注关键样式调用的地方）；
  4. 页面进行标注（例如 页面 模块 开始和结束）；
  5. CSS跟HTML 分文件夹并行存放，命名都得统一（例如style.css）；
  6. JS 分文件夹存放 命名以该JS功能为准的英文翻译。
  7. 图片采用整合的 images.png png8 格式文件使用 尽量整合在一起使用方便将来的管理 
---

# 对前端界面工程师这个职位是怎么样理解的？它的前景会怎么样？
    <1>.前端是最贴近用户的程序员，比后端、数据库、产品经理、运营、安全都近。
    	1)、实现界面交互
    	2)、提升用户体验
    	3)、有了Node.js，前端可以实现服务端的一些事情

    <2>.前端是最贴近用户的程序员，前端的能力就是能让产品从 90分进化到 100 分，甚至更好，

    <3>.参与项目，快速高质量完成实现效果图，精确到1px；

    <4>.与团队成员，UI设计，产品经理的沟通；

    <5>.做好的页面结构，页面重构和用户体验；

    <6>.处理hack，兼容、写出优美的代码格式；

    <7>.针对服务器的优化、拥抱最新前端技术。

# 谈谈以前端角度出发做好SEO需要考虑什么？
  1. 了解搜索引擎如何抓取网页和如何索引网页:  你需要知道一些搜索引擎的基本工作原理，各个搜索引擎之间的区别，搜索机器人（SE robot 或叫 web crawler）如何进行工作，搜索引擎如何对搜索结果进行排序等等。
  2. Meta标签优化: 主要包括主题（Title)，网站描述(Description)，和关键词（Keywords）。还有一些其它的隐藏文字比如Author（作者），Category（目录），Language（编码语种）等。
  3. 如何选取关键词并在网页中放置关键词:  首先要给网站确定主关键词（一般在5个上下），然后针对这些关键词进行优化，包括关键词密度（Density），相关度（Relavancy），突出性（Prominency）等等
  4. 了解主要的搜索引擎： 不同的搜索引擎对页面的抓取和索引、排序的规则都不一样。还要了解各搜索门户和搜索引擎之间的关系，比如AOL网页搜索用的是Google的搜索技术，MSN用的是Bing的技术。
  5. 主要的互联网目录
  6. 按点击付费的搜索引擎
  7. 链接交换和链接广泛度
  8. 合理的标签使用
---

# WEB应用从服务器主动推送Data到客户端有那些方式？
  1. html5 websoket
  2. WebSocket通过Flash
  3. XHR长时间连接
  4. XHR Multipart Streaming
  5. 不可见的Iframe
  6. `<script>`标签的长时间连接(可跨域)
---

# 移动端的点击事件的有延迟，时间是多久，为什么会有？ 怎么解决这个延时？
  300ms
---

# 使用CDN有什么好处
  * 使用CDN可以给你的网站加速，本身不影响SEO正常收录和网站优化，相反，还能提升你的网站用户体验，隐藏你的源站IP防止被黑客攻击；
---

# JWT的优缺点, 使用场景?
  * 优点:
    - 可扩展性好：应用程序分布式部署的情况下，session需要做多机数据共享，通常可以存在数据库或者redis里面。而jwt不需要。

    - 无状态: jwt不在服务端存储任何状态。jwt可以存储一些常用信息, 有效地使用 JWT，可以降低服务器查询数据库的次数。

  * 缺点:
   	- 安全性： 由于jwt的payload是使用base64编码的，并没有加密，因此jwt中不能存储敏感数据。而session的信息是存在服务端的，相对来说更安全。

   	- 性能：
   	jwt太长。由于是无状态使用JWT，所有的数据都被放到JWT里，如果还要进行一些数据交换，那载荷会更大，经过编码之后导致jwt非常长，cookie的限制大小一般是4k，cookie很可能放不下，所以jwt一般放在local storage里面。并且用户在系统中的每一次http请求都会把jwt携带在Header里面，http请求的Header可能比Body还要大。而sessionId只是很短的一个字符串，因此使用jwt的http请求比使用session的开销大得多。

   	- 一次性： 无状态是jwt的特点，但也导致了这个问题，jwt是一次性的。想修改里面的内容，就必须签发一个新的jwt。

  * 场景:
	  - 有效期短

	  - 只希望被使用一次。jwt具有一次性的特性。单点登录和会话管理非常不适合用jwt，如果在服务端部署额外的逻辑存储jwt的状态，那还不如使用session。
---

# 从浏览器地址栏输入url到显示页面的步骤(以HTTP为例)
  1. 输入网址；
  2. 发送到DNS服务器，并获取域名对应的web服务器对应的ip地址；
  3. 与web服务器建立TCP连接；
  4. 浏览器向web服务器发送http请求；
  5. web服务器响应请求，并返回指定url的数据（或错误信息，或重定向的新的url地址）；
  6. 浏览器下载web服务器返回的数据及解析html源文件；
  7. 生成DOM树，解析css和js，渲染页面，直至显示完成；
---

# dns查询过程，使用的协议
---

# HTTP request报文结构是怎样的
  * 首行是Request-Line包括：请求方法，请求URI，协议版本，CRLF
  * 首行之后是若干行请求头，包括general-header，request-header或者entity-header，每个一行以CRLF结束
  * 请求头和消息实体之间有一个CRLF分隔
  * 根据实际请求需要可能包含一个消息实体
---

# HTTP response报文结构是怎样的
  * 首行是状态行包括：HTTP版本，状态码，状态描述，后面跟一个CRLF
  * 首行之后是若干行响应头，包括：通用头部，响应头部，实体头部
  * 响应头部和响应实体之间用一个CRLF空行分隔
  * 最后是一个可能的消息实体
---

# 线程与进程的区别
  * 一个程序至少有一个进程,一个进程至少有一个线程. 
  * 线程的划分尺度小于进程，使得多线程程序的并发性高。
  * 另外，进程在执行过程中拥有独立的内存单元，而多个线程共享内存，从而极大地提高了程序的运行效率。 
  * 线程在执行过程中与进程还是有区别的。每个独立的线程有一个程序运行的入口、顺序执行序列和程序的出口。但是线程不能够独立执行，必须依存在应用程序中，由应用程序提供多个线程执行控制。 
  * 从逻辑角度来看，多线程的意义在于一个应用程序中，有多个执行部分可以同时执行。但操作系统并没有将多个线程看做多个独立的应用，来实现进程的调度和管理以及资源分配。这就是进程和线程的重要区别。
---

# http状态码有那些？分别代表是什么意思？
  * 100-199 用于指定客户端应相应的某些动作。 
  * 200-299 用于表示请求成功。 
  * 300-399 用于已经移动的文件并且常被包含在定位头信息中指定新的地址信息。 
  * 400-499 用于指出客户端的错误。400    1、语义有误，当前请求无法被服务器理解。401   当前请求需要用户验证 403  服务器已经理解请求，但是拒绝执行它。
  * 500-599 用于支持服务器错误。 503 – 服务不可用
---

# 前端安全问题？
  XSS，sql注入，CSRF
---

# 请解释一下csrf 和 xss；
  * xss：恶意攻击者往 Web 页面里插入恶意 Script 代码，当用户浏览该页之时，嵌入其中 Web 里面的 Script 代码会被执行，从而达到恶意攻击用户的目的。

  * csrf：CSRF 攻击是攻击者借助受害者的 Cookie 骗取服务器的信任，可以在受害者毫不知情的情况下以受害者名义伪造请求发送给受攻击服务器，从而在并未授权的情况下执行在权限保护之下的操作。
---

# 怎么防止 csrf 和 xss？
---

# XSS是什么，攻击原理，怎么预防。
---

# GET和POST的区别，何时使用POST？
  * 区别:
    1. GET：一般用于信息获取，使用URL传递参数，对所发送信息的数量也有限制，一般在2000个字符
    2. POST：一般用于修改服务器上的资源，对所发送的信息没有限制。
    3. GET方式需要使用Request.QueryString来取得变量的值，而POST方式通过Request.Form来获取变量的值，也就是说Get是通过地址栏来传值，而Post是通过提交表单来传值。

  * 然而，在以下情况中，请使用 POST 请求：
    1. 无法使用缓存文件（更新服务器上的文件或数据库）
    2. 向服务器发送大量数据（POST 没有数据量限制）
---

# x-www-urlecoded-form和application/json在post中的区别
  * application/x-www-form-urlencoded：我bai们form表单提交就是这个模式，du并且将zhi提交的数据进行daourlencode。默认情况下，我zhuan们所有的表单提交都是通过这种默shu认的方式实现的。最常用的一种。

  * application/json：采用json格式提交，比如我们常用的ajax，dataType:"json"
---

# 说说TCP传输的三次握手四次挥手策略
  * 三次握手:
    1. 为了准确无误地把数据送达目标处，TCP协议采用了三次握手策略。用TCP协议把数据包送出去后，TCP不会对传送 后的情况置之不理，它一定会向对方确认是否成功送达。握手过程中使用了TCP的标志：SYN和ACK。

    2. 发送端首先发送一个带SYN标志的数据包给对方。接收端收到后，回传一个带有SYN/ACK标志的数据包以示传达确认信息。

    3. 最后，发送端再回传一个带ACK标志的数据包，代表“握手”结束。 若在握手过程中某个阶段莫名中断，TCP协议会再次以相同的顺序发送相同的数据包。

  * 断开一个TCP连接则需要“四次挥手”：
    1. 第一次挥手：主动关闭方发送一个FIN，用来关闭主动方到被动关闭方的数据传送，也就是主动关闭方告诉被动关闭方：我已经不 会再给你发数据了(当然，在fin包之前发送出去的数据，如果没有收到对应的ack确认报文，主动关闭方依然会重发这些数据)，但是，此时主动关闭方还可 以接受数据。

    2. 第二次挥手：被动关闭方收到FIN包后，发送一个ACK给对方，确认序号为收到序号+1（与SYN相同，一个FIN占用一个序号）。

    3. 第三次挥手：被动关闭方发送一个FIN，用来关闭被动关闭方到主动关闭方的数据传送，也就是告诉主动关闭方，我的数据也发送完了，不会再给你发数据了。

    4. 第四次挥手：主动关闭方收到FIN后，发送一个ACK给被动关闭方，确认序号为收到序号+1，至此，完成四次挥手。
---

# HTTP和HTTPS的区别。https怎么实现它的安全性的？
  * HTTP协议通常承载于TCP协议之上，在HTTP和TCP之间添加一个安全协议层（SSL或TSL），这个时候，就成了我们常说的HTTPS。默认HTTP的端口号为80，HTTPS的端口号为443。
---

# HTTPS原理及过程
---

# HTTP协议有什么特点？
  1. 简单快速：客户向服务器请求服务时，只    需传送请求方法和路径。请求方法常用的有GET、HEAD、POST等。每种方法规定了客户与服务器联系的类型不同。由于HTTP协议简单，使得HTTP服务器的程序规模小，因而通信速度很快。

  2. 灵活：HTTP允许传输任意类型的数据对象。正在传输的类型由Content-Type加以标记。

  3. HTTP 0.9和1.0使用非持续连接：限制每次连接只处理一个请求。服务器处理完客户的请求，并收到客户的应答后，即断开连接。HTTP 1.1使用持续连接：不必为每个web对象创建一个新的连接，一个连接可以传送多个对象，采用这种方式可以节省传输时间。

  4. 无状态：HTTP协议是无状态协议。无状态是指协议对于事务处理没有记忆能力。缺少状态意味着如果后续处理需要前面的信息，则它必须重传，这样可能导致每次连接传送的数据量增大。另一方面，在服务器不需要先前信息时它的应答就较快。

  5. 支持B/S(Browser/Server,浏览器/服务器方式的网络结构。)及C/S(Client/Server,客户/服务器方式的网络计算模式)模式。
---

# WebSocket和HTTP之间的关系
  1. WebSocket和HTTP一样都是基于TCP的应用层协议。

  2. WebSocket协议和HTTP协议是两种不同的东西。客户端开始建立WebSocket连接时要发送一个header标记了 Upgrade的HTTP请求，表示请求协议升级。所以服务器端做出响应的简便方法是，直接在现有的HTTP服务器软件和现有的端口上实现WebSocket协议，然后再回一个状态码为101的HTTP响应完成握手，再往后发送数据时就没 HTTP的事了。也就是说WebSocket只是使用HTTP协议来完成一部分握手。
  
  3. http无状态、被动；ws一次握手，知道状态，可以双向通信
---

# REST是什么, 为什么使用它?
---

# 浏览器渲染的整个过程
---

# 遇到过哪些移动端兼容问题？
---

# 如何优化SPA应用的首屏加载速度慢的问题？
  1. 将公用的JS库通过script标签外部引入，减小app.bundel的大小，让浏览器并行下载资源文件，提高下载速度；
  2. 在配置 路由时，页面和组件使用懒加载的方式引入，进一步缩小 app.bundel 的体积，在调用某个组件时再加载对应的js文件；
  3. 加一个首屏 loading 图，提升用户体验；
---

# 说说http 与 tcp 的关系
---

# tcp 可以建立多个连接吗？
---

# tcp如何保证安全连接
---

# 怎么知道一个tcp请求数据已经完了呢
---

# 项目里面的鉴权和图片懒加载怎么实现的
---

# 如何更好的处理线上的日志？
  1. 日志分级输出，可以分业务日志错误日志等
  2. 可以把日志交给spring管理，定期扫描配置文件达到无需重启的目的，定位到原因就可以把级别调回去
  3. 把日志放到WEB目录，通过权限限制外网直接访问，达到浏览器就可以查看日志
---

# 组件设计原则。
  1. 层次结构和 UML 类图；
  2. 扁平化、面向数据的 state/props；
  3. 更加纯粹的 State 变化；
  4. 低耦合；
  5. 辅助代码分离；
  6. 及时模块化；
  7. 集中/统一的状态管理；
---

# websocket是什么，原理，怎么实现
---

# web worker有什么用，什么样的场景比较适合？
---

# 发布订阅模式和观察者模式的异同。
---

# TCP/IP有几层网络模型，都是做什么的
---

# 数组和链表的区别
    数组易读取，链表只能一个个读或者需要额外空间才能易读取；数组增删元素需要照顾index，链表不用
---