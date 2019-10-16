

![](http://ww1.sinaimg.cn/large/7fa2dba2gy1g8052hcg3aj20yg0blq9k.jpg)


# 记录

[个人博客记录](https://guanhui07.github.io/blog/)

[about me](https://about.me/yangminghui)

wordpress -> Octopress -> markdown 文本 -> github

我关注技术或学习的渠道 包括app  web 小程序

laravel-china https://laravel-china.org/users/1670

github &博客  https://github.com/guanhui07

开发者头条 https://toutiao.io/u/484739?f=new

开源中国  https://my.oschina.net/u/1417003

gitChat  https://gitbook.cn/gitchat/ordered

微信公众号

知乎 https://www.zhihu.com/people/guanhui07/activities

掘金 https://juejin.im/user/576f2f6f816dfa0055dbe88a

segmentfault https://segmentfault.com/u/guanhui07

微博  https://weibo.com/2141379490/profile?rightmod=1&wvr=6&mod=personinfo&is_all=1

Twitter  https://twitter.com/guanhui07

简书 https://www.jianshu.com/u/e479b3bdeb65

openresty社区 https://groups.google.com/forum/#!forum/openresty

无码科技 https://readhub.cn/topics

golang社区 https://studygolang.com/

ruby-china社区 https://ruby-china.org/

python社区 https://learnku.com/python

orchina http://orchina.org/

图灵社区 http://www.ituring.com.cn/book

豆瓣  https://book.douban.com/

gitee https://gitee.com/guanhui07

infoq https://infoq.cn/profile/1057668

推酷 https://www.tuicool.com/ah/20/

极客时间

得到

微信读书

瓦斯阅读 https://w.qnmlgb.tech/wx

喜马拉雅app web https://www.ximalaya.com/

技术周刊  https://github.com/ruanyf/weekly

各类博客  v2ex 知识星球等等 


多看书，网络获取知识都是靠积累。




### 通过js介绍自己
```javascript
(function(nick, createAt) {
 
  const now = (new Date).getFullYear();
 
  class Person {
    constructor(params) {
      Person.iterationHelper(params, (prop) => this[prop] = params[prop]);
    }
 
    set dreamCode(val) {
      this.Dream = String.fromCharCode.apply(null, val);
      delete this.dreamCode;
    }
 
    static iterationHelper(data, fn) {
      Object.keys(data).forEach(fn);
    }
 
    static introduce(content) {
      console.log(content);
    }
  }
 
  const dreamCode = [
    0x42,
    0x65, 0x63,
    0x6f, 0x6d, 0x65,
    0x20, 0x61, 0x20, 0x72,
    0x65, 0x73, 0x70, 0x65, 0x63,
    0x74, 0x65, 0x64, 0x20, 0x70, 0x72,
    0x6f, 0x67, 0x72, 0x61,
    0x6d, 0x6d, 0x65, 0x72, 0x2c, 0x20,
    0x63, 0x6f, 0x64, 0x65, 0x20,
    0x74, 0x68, 0x65, 0x20,
    0x77, 0x6f, 0x72,
    0x6c, 0x64,
    0x2e,
  ];
  const name = 'yang';
  const sex = '男';
  const age = now - createAt;
  let tags = ['私有云', '工程工具', '后端', '数据'];
  let hobby = ['篮球', '游泳'];
 
  let me = new Person({name, sex, age, nick, dreamCode, tags, hobby});
 
  with (Person) iterationHelper(me, (n) => introduce(`${n.replace(/^\w/, c => c.toUpperCase())}:\t${me[n]}`));
 
})('guanhui07', 0x07c4);

```




```
                             #               "     mmmm  mmmmmm
  mmmm  m   m   mmm   m mm   # mm   m   m  mmm    m"  "m     #"
 #" "#  #   #  "   #  #"  #  #"  #  #   #    #    #  m #    m"
 #   #  #   #  m"""#  #   #  #   #  #   #    #    #    #   m"
 "#m"#  "mm"#  "mm"#  #   #  #   #  "mm"#  mm#mm   #mm#   m"
  m  #
   ""
```
