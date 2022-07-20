# SM3的Rho 攻击

  使用的SM3代码为从 [SM3算法的C++实现（代码）_清梦长安的博客-CSDN博客_sm3实现](https://blog.csdn.net/nicai_hualuo/article/details/121555000)中所得到的C++源码。

  主要的逻辑为希望能够构造一个环，代码逻辑如下所

$$
\begin{aligned}
&input:\{0,1\}^l\\
&output:x,x' with \ H(x)=H(x')\\
&x_0 =\{0,1\}^{l+1}\\
&x'=x=x_0\\
&while(1):\\
&\ \ x=H(x)\\
&\ \ x'=H(H(x'))\\
&\ \ x=H(x)\\
&\ \ if\ x=x'\ break\\
&x'=x \ x=x_0\\
&while(1)\\
&\ \ if(H(x)=H(x'))\ return \ x,x'\\
&\ \ else\ x=H(x),x'=H(x')
\end{aligned}
$$

其中为了减少攻击难度，hash值只取高位

得到16bit结果如下

3D9A6ACCAF0D0E0C20BB932A8DF0D351231C794D82553D921BC3FF66535EB11B
6716D98006E20244489BF5A9B60C6A37F51A214511AFDDED9D4A6AC53A02B167

![0](.\成果截图.png)
