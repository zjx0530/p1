
import socket
from gmssl import sm2 ,sm4
import sys
import random 
from Crypto.Util.number import *
from hashlib import sha256
from Crypto.Protocol.KDF import scrypt
#import Crypto.Util.number

salt=b'\x00'*32

ecctable = {
    'n': 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123',
    'p': 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF',
    'g': '32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7'\
         'bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0',
    'a': 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC',
    'b': '28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93',
}

Z='happy'#identifier for both parties  随意

def generate_d1():
    """
    产生初始的d1
    """
    n=int(ecctable['n'],16)
    d1=random.randint(1,n-1)
    return d1


def generate_P1(d1):
    """
    用来产生P1
    """
    n=int(ecctable['n'],16)
    sm2_c=sm2.CryptSM2(private_key="",public_key="")
    P1=sm2_c._kg(inverse(d1,n),ecctable['g'])
    return P1

def Encrypt_2p(k,P,m):
    """
    加密函数
    """
    m=str(m)
    n=int(ecctable['n'],16)
    sm2_c=sm2.CryptSM2(private_key="",public_key="")
    C1=sm2_c._kg(k,ecctable['g'])
    KP=sm2_c._kg(k,P)
    t=scrypt(KP,salt,32,2**14,8,1,1)
    t=int(t.hex(),16)
    m_int=int(str(m).encode('utf-8').hex(),16)
    C2=m_int^t
    C2=hex(m_int^t)[2:]
    len1=len(KP)
    C3=sha256(KP[0:sm2_c.para_len].encode('utf-8')+m.encode('utf-8')+KP[sm2_c.para_len:len1].encode('utf-8')).digest()
    return (C1,C2,C3)


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




#----------------test--------------


m=input("请输入您想要加密的消息：")

HOST = '127.0.0.1'
PORT = 50007
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    s.connect((HOST, PORT))
except Exception as e:
    print('Server not found or not open')
    sys.exit()


d1=generate_d1()
P1=generate_P1(d1)
s.sendall(P1.encode('utf-8'))#发送P1
P = s.recv(1024).decode('utf-8')
k=generate_d1()#生成一个随机数（0，n-1）
C1,C2,C3=Encrypt_2p(k,P,m)#此处利用加密生成了所有的密文

assert C1!='',"C1=0"

n=int(ecctable['n'],16)
sm2_c=sm2.CryptSM2(private_key="",public_key="")
T1=sm2_c._kg(inverse(d1,n),C1)

s.sendall(T1.encode('utf-8'))#发送T1
T2= s.recv(1024).decode('utf-8')#接受T2

C1_1=generate_G_1(C1)

KP=sm2_c._add_point(T2,C1_1)#两个点相加
KP=sm2_c._convert_jacb_to_nor(KP)#得到最终的x||y

t=scrypt(KP,salt,32,2**14,8,1,1)
t=int(t.hex(),16)
m_d=hex(int(C2,16)^t)[2:]
m_d=bytes().fromhex(m_d).decode('utf-8')
len1=len(KP)
u=sha256(KP[0:sm2_c.para_len].encode('utf-8')+m_d.encode('utf-8')+KP[sm2_c.para_len:len1].encode('utf-8')).digest()

if u==C3 :
    print('解密成功,解密结果：',m_d)