import ecdsa
import random
from hashlib import sha256
from Crypto.Util.number import *

G=ecdsa.NIST256p.generator#获得NIST256p的生成元
n=G.order()#NIST256p椭圆曲线的阶
privateKey = random.randint(1,n-1)#生成一个随机私钥
print("假设的saotoshi的私钥",privateKey)
P=G*privateKey#此为公钥
publicKey = ecdsa.ecdsa.Public_key(G,G * privateKey)#生成公钥对象

#两个随机数u，v
u=random.randint(1,n-1)
v=random.randint(1,n-1)

R=G.mul_add(u,P,v)#此为u*G+v*P
x1=R.x()#此为x
r1=x1%n
e1=(r1*u*inverse(v,n))%n
s1=(r1*inverse(v,n))%n
print("伪造签名(r,s):(%d,%d)"%(r1,s1),"对应的消息签名为：",e1)
sig=ecdsa.ecdsa.Signature(r1,s1)

print("验证结果",publicKey.verifies(e1,sig))
