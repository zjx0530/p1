# MD5的长度扩展攻击

  使用的MD5代码为从 https://baike.baidu.com/item/MD5/212708?fr=aladdin 中所得到的C++源码。

  在进行长度扩展攻击时，首先自行输入需要攻击的信息字符串M，然后对这个M进行填充后得到M+padding，然后得到H(M)。由于MD5有填充，所以我们需要知道原来的M+padding的长度。在已知H(M)和M+padding的长度的前提下，我们构建一个跟M+padding一样长的字符串（为64字节倍数）。将需要添加的信息append 添加到这个字符串后面，然后进行填充。

  自己创建一个新的计算MD5的函数，并且开始计算杂凑值，在计算到append之前，将A,B,C,D对应的中间变量替换为H(M)对应的值，然后继续计算，最终的输出结果就是H(M+padding+append)。

## 