# 使用了RFC6979 确定性签名算法的SM2

  

  由于重点是生成k，所以sm2算法使用了gmssl库。

  在生成k的时候，完全按照RFC6979的标准实行：

   Generation of k
   
   Given the input message m, the following process is applied:
   
   a.  Process m through the hash function H, yielding:
   
          h1 = H(m)
          
       (h1 is a sequence of hlen bits).
       
   b.Set
   
          V = 0x01 0x01 0x01 ... 0x01 
          
       such that the length of V, in bits, is equal to 8*ceil(hlen/8).
       For instance, on an octet-based system, if H is SHA-256, then V
       is set to a sequence of 32 octets of value 1.  Note that in this
       step and all subsequent steps, we use the same H function as the
       one used in step 'a' to process the input message; this choice
       will be discussed in more detail in Section 3.6.
       
   c.  Set:
   
          K = 0x00 0x00 0x00 ... 0x00
       such that the length of K, in bits, is equal to 8*ceil(hlen/8).
       
   d.  Set:
   
          K = HMAC_K(V || 0x00 || int2octets(x) || bits2octets(h1))
       where '||' denotes concatenation.  In other words, we compute
       HMAC with key K, over the concatenation of the following, in
       order: the current value of V, a sequence of eight bits of value
       0, the encoding of the (EC)DSA private key x, and the hashed
       message (possibly truncated and extended as specified by the
       bits2octets transform).  The HMAC result is the new value of K.
       Note that the private key x is in the [1, q-1] range, hence a
       proper input for int2octets, yielding rlen bits of output, i.e.,
       an integral number of octets (rlen is a multiple of 8).
       
   e.  Set:
   
          V = HMAC_K(V)
   f.  Set:
   
          K = HMAC_K(V || 0x01 || int2octets(x) || bits2octets(h1))
       Note that the "internal octet" is 0x01 this time.
       
   g.  Set:
   
          V = HMAC_K(V)
          
   h.  Apply the following algorithm until a proper value is found for
   
       k:
       
       1.  Set T to the empty sequence.  The length of T (in bits) is
           denoted tlen; thus, at that point, tlen = 0.
           
       2.  While tlen < qlen, do the following:
              V = HMAC_K(V)
              T = T || V



  测试方法：直接输入想要签名的字符串，然后就会展示是否验证成功

  
