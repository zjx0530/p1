
import socket
from gmssl import sm2 ,sm4
import sys
import random 
from Crypto.Util.number import *
from hashlib import sha256
#import Crypto.Util.number

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

def generate_Q1_e(m,z):
    """
    产生需要的Q1,e
    z和m都是字符串
    """
    e=sha256(z.encode('utf-8')+m.encode('utf-8')).digest()
    k1=generate_d1()
    n=int(ecctable['n'],16)
    sm2_c=sm2.CryptSM2(private_key="",public_key="")
    Q1=sm2_c._kg(k1,ecctable['g'])
    return(Q1,e,k1)

def generate_sign(k1,d1,r,s2,s3):
    n=int(ecctable['n'],16)
    s=((d1*k1)*s2+d1*s3-r)%n
    if s!=0 and s!=n-r : 
        return(r,s)


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
an = s.recv(1024)
assert an.decode('utf-8')=="OK","fail1"

Q1,e,k1=generate_Q1_e(m,Z)#产生并发送Q1,e,k1
s.sendall(Q1.encode('utf-8'))
an = s.recv(1024)
assert an.decode('utf-8')=="OK","fail2"

s.sendall(e)
an = s.recv(1024)
assert an.decode('utf-8')=="OK","fail3"



r=int(s.recv(1024).decode("utf-8"),16)#一下是接受r,s2,s3
s.sendall("OK".encode('utf-8'))
s2=int(s.recv(1024).decode("utf-8"),16)
s.sendall("OK".encode('utf-8'))
s3=int(s.recv(1024).decode("utf-8"),16)
s.sendall("OK".encode('utf-8'))

r,s=generate_sign(k1,d1,r,s2,s3)#产生签名
print("产生的签名(r,s):",r,s)