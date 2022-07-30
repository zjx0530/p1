import ecdsa
from hashlib import sha256
from Crypto.Util.number import *
from gmssl import sm2 ,sm4,func
import random 

#以下是通用的sm2的公私钥
private_key= '00B9AB0B828FF68872F21A837FC303668428DEA11DCD1B24429D0C99E24EED83D5'
public_key = 'B9C9A6E04E9C91F7BA880429273747D7EF5DDEB0BB2FF6317EB00BEF331A83081A6994B8993F3F5D6EADDDB81872266C87C018FB4162F5AF347B483E24620207'
#sm2圆锥曲线的参数
ecctable = {
    'n': 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123',
    'p': 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF',
    'g': '32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7'\
         'bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0',
    'a': 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC',
    'b': '28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93',
}
#sm2椭圆曲线的阶
N=int(ecctable['n'],16)


def leaking_k(k,r,s):
    """
    丢失k导致丢失d
    此处的参数都是int类型
    """
    d=(inverse((s+r),N)*(k-s))%N

    return d

def reusing_k(r1,s1,r2,s2):

    t=(s2-s1)%N
    t2=inverse(s1-s2+r1-r2,N)
    d=(t*t2)%N
    return d

def reusing_k_by_different_user(r,s,k):

    t=(k-s)%N
    t2=inverse(s+r,N)
    d=(t*t2)%N
    return d

def ECDSA_sign(m,k,d):
    """
    利用sm2曲线的参数来计算
    """
    sm2_c=sm2.CryptSM2(private_key=d,public_key="")
    R=sm2_c._kg(k,ecctable["g"])
    r=int(R[0:sm2_c.para_len],16)%N
    E = m.hex() # 消息转化为16进制字符串
    e = int(E, 16)
    s=((e+r*int(d,16))*inverse(k,N))%N
    k1=(int(d,16)*r+e)*inverse(s,N)
    k1=k1%N

    return (r,s,e)

def sm2_sign(m,k,d):
    E = m.hex() # 消息转化为16进制字符串
    e = int(E, 16)
    sm2_c=sm2.CryptSM2(private_key=d,public_key="")
    R=sm2_c._kg(k,ecctable["g"])
    r=(e+int(R[0:sm2_c.para_len],16))%N
    s=inverse(1+int(d,16),N)*(k-r*int(d,16))
    return(r,s)

def same_d_and_k_with_ECDSA(e1,r1,s1,r2,s2):
    t1=(s1*s2-e1)%N
    t2=inverse(r1-s1*s2-s1*r2,N)
    d=(t1*t2)%N
    return d


#------------丢失k导致丢失私钥d--------------

sm2_crypt=sm2.CryptSM2(private_key=private_key,public_key=public_key)#设置好加解密器

data = b"111" # bytes类型
random_hex_str = func.random_hex(sm2_crypt.para_len)
sign = sm2_crypt.sign(data, random_hex_str) #  16进制

k=int(random_hex_str,16)
r = int(sign[0:sm2_crypt.para_len], 16)
s = int(sign[sm2_crypt.para_len:2*sm2_crypt.para_len], 16)
print("----------丢失k导致丢失私钥d---------")
d1=leaking_k(k,r,s)
if d1==int(private_key,16):
    print("攻击成功")
print("------------------------------------")


#------------重复使用k导致私钥d泄露——
random_hex_str = func.random_hex(sm2_crypt.para_len)
#签名第一次
data = b"111" 
sign1 = sm2_crypt.sign(data, random_hex_str) #  16进制
r1 = int(sign1[0:sm2_crypt.para_len], 16)
s1 = int(sign1[sm2_crypt.para_len:2*sm2_crypt.para_len], 16)
#同一个k签名第二次
data = b"222" # bytes类型
sign2 = sm2_crypt.sign(data, random_hex_str) #  16进制
r2 = int(sign2[0:sm2_crypt.para_len], 16)
s2 = int(sign2[sm2_crypt.para_len:2*sm2_crypt.para_len], 16)
print("---------重复使用k攻击------------")
d1=reusing_k(r1,s1,r2,s2)
if d1==int(private_key,16):
    print("攻击成功")
print("---------------------------------")

#---------------不同用户使用相同的k导致密钥泄露----------

random_hex_str = func.random_hex(sm2_crypt.para_len)
k=int(random_hex_str,16)
dA=func.random_hex(64)#256bit私钥
A=sm2.CryptSM2(private_key=dA,public_key="")#此处用不上所以不要了
data = b"111" 
signA=A.sign(data, random_hex_str)
rA = int(signA[0:sm2_crypt.para_len], 16)
sA = int(signA[sm2_crypt.para_len:2*sm2_crypt.para_len], 16)

dB=func.random_hex(64)#256bit私钥
B=sm2.CryptSM2(private_key=dB,public_key="")#此处用不上所以不要了
data = b"222" 
signB=B.sign(data, random_hex_str)
rB = int(signB[0:sm2_crypt.para_len], 16)
sB = int(signB[sm2_crypt.para_len:2*sm2_crypt.para_len], 16)


print("---------不同用户使用相同的k导致密钥泄露------------")
da=reusing_k_by_different_user(rA,sA,k)

if(da==int(dA,16)):
    print("猜测A私钥成功")

db=reusing_k_by_different_user(rB,sB,k)

if(db==int(dB,16)):
    print("猜测B私钥成功")
print("--------------------------------------------------")


#-----------------same d and k with ECDSA-----------

random_hex_str = func.random_hex(64)
k=int(random_hex_str,16)
d=func.random_hex(64)#256bit私钥
d_i=int(d,16)
data = b"222" 
r1,s1,e1=ECDSA_sign(data,k,d)



data = b"111" 
sm2_cry=sm2.CryptSM2(private_key=d,public_key="")
sign=sm2_cry.sign(data, random_hex_str)
r2 = int(sign[0:sm2_cry.para_len], 16)
s2 = int(sign[sm2_cry.para_len:2*sm2_cry.para_len], 16)
#r2,s2=sm2_sign(data,k,d)




d1=same_d_and_k_with_ECDSA(e1,r1,s1,r2,s2)


print("---------same d and k with ECDSA------------")

if(d1==int(d,16)):
    print("攻击成功")
print("--------------------------------------------------")

#--------------  r,-s也是合法签名--------------
print("r,-s也是合法签名")
gen=ecdsa.NIST256p.generator
rank=gen.order()
privateKey = random.randrange(1,rank-1)
publicKey = ecdsa.ecdsa.Public_key(gen,gen * privateKey)
private_key = ecdsa.ecdsa.Private_key(publicKey,privateKey)
message = "zhangjixian"
m = int(sha256(message.encode("utf8")).hexdigest(),16)
k = random.randrange(1,rank-1)
signature = private_key.sign(m,k)
print("原来的签名（r,s）验证结果：",publicKey.verifies(m, signature))
r = signature.r
s = signature.s
s=-s%rank
signature.s=s
print("现在的签名（r,-s）验证结果：",publicKey.verifies(m, signature))