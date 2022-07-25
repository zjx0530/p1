
import random
from gmssl import sm2
from hashlib import sha256
import argon2


ecctable = {
    'n': 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123',
    'p': 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF',
    'g': '32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7'\
         'bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0',
    'a': 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC',
    'b': '28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93',
}
str36='qwertyuiopasdfghjklzxcvbnm1234567890'

def generate_p_u():
    """
    password and username 
    """
    u=''
    for i in range(0,random.randint(10,20)):
        u+=str36[random.randint(0,35)]
    p=''
    for i in range(0,random.randint(10,20)):
        p+=str36[random.randint(0,35)]
    return (p,u)


def generate_a():
    """
    产生a
    """
    n=int(ecctable['n'],16)
    d1=random.randint(1,n-1)
    return d1

def ECMH(h):
    """
    将h hash到曲线上
    """
    hash_256=sha256(h).digest()
    while(int(hash_256.hex(),16)>=int(ecctable['n'],16)):#为了让这个值处于（0，n-1）之间，如果大了就加盐
        hash_256=sha256(b'\x00'+hash_256)
    pri=int(hash_256.hex(),16)
    sm2_c=sm2.CryptSM2(private_key="",public_key="")#因为只是利用其中函数所以不设置公钥私钥
    P1=sm2_c._kg(pri,ecctable['g'])#此处计算了哈希值*G后点的坐标x||y
    return P1

def generate_G_1(G):
    """
    产生-G
    """
    sm2_c=sm2.CryptSM2(private_key="",public_key="")
    leng=len(G)
    xg=G[0:sm2_c.para_len]
    yg=G[sm2_c.para_len:leng]
    yg=int(yg,16)
    yg=(-yg)%int(ecctable['p'],16)
    yg=hex(yg)[2:]
    G_1=xg+yg
    return G_1

#-------------test--------------------

#以下是用户自己的生成

SM=sm2.CryptSM2('','')

a=generate_a()

p,u=generate_p_u()#自己的用户名密码

h=argon2.argon2_hash(p,u)
k=h[:2]

h=ECMH(h)

temp=SM._kg(a,ecctable['g'])
v=SM._add_point(temp,h)#两个点相加
v=SM._convert_jacb_to_nor(v)#得到最终的x||y


#以下是库的生成
b=generate_a()

data_base=dict()

for i in range(0,100):
    p1,u1=generate_p_u()
    h1=argon2.argon2_hash(p1,u1)
    k1=h[:2]
    h1=ECMH(h1)
    temp=SM._kg(b,ecctable['g'])
    v1=SM._add_point(temp,h1)#两个点相加
    v1=SM._convert_jacb_to_nor(v1)#得到最终的x||y
    if k1 not in data_base.keys():
        data_base[k1]=[v1,]
    else:
        data_base[k1].append(v1)
    

temp=SM._kg(b,ecctable['g'])
v_s=SM._add_point(temp,h)#两个点相加
v_s=SM._convert_jacb_to_nor(v_s)#得到最终的x||y
if k not in data_base.keys():
    data_base[k]=[v_s,]
else:
    data_base[k].append(v_s)

#根据库查找k,v ,并返回hab和set的东西

temp=SM._kg(b,ecctable['g'])
h_ab=SM._add_point(temp,v)
h_ab=SM._convert_jacb_to_nor(h_ab)
set=data_base[k]

#用户根据返回的以上信息来看自己的密码是否在其中

temp=SM._kg(a,ecctable['g'])
temp=generate_G_1(temp)
h_b=SM._add_point(temp,h_ab)#两个点相加
h_b=SM._convert_jacb_to_nor(h_b)#得到最终的x||y
if h_b in set:
    print("用户名：",u,"密码：",p,"已经被盗了")

