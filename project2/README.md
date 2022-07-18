# SM3的生日攻击

  使用的SM3代码为从 [SM3算法的C++实现（代码）_清梦长安的博客-CSDN博客_sm3实现](https://blog.csdn.net/nicai_hualuo/article/details/121555000)中所得到的C++源码。

  利用了map来进行字典攻击，随机生成32长的字符串，计算其杂凑值并且将杂凑值的前16（或者32位）作为键，字符串作为值。每次生成了杂凑值检索一下有没有对应的键值对，如果有则碰撞成功。

找到SM3 高32位的一个碰撞，以下两个字符串产生杂凑值的高32位相同。
vnweagujcrxkqanmxeytygwvuefyfngs
vgzvctqsrfglztxukavxdmnnpmhhutuo