import socket
from gmssl import sm2 ,sm4
import sys
import random 
from Crypto.Util.number import *
#inverse(3,7)





ecctable = {
    'n': 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123',
    'p': 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF',
    'g': '32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7'\
         'bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0',
    'a': 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC',
    'b': '28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93',
}



def generate_d2():
    n=int(ecctable['n'],16)
    d1=random.randint(1,n-1)
    return d1

def generate_G_1(G):
    """
    产生-G，实现椭圆曲线减法
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


def generate_P(d2,P1):
    """
    产生公钥
    """
    n=int(ecctable['n'],16)
    sm2_c=sm2.CryptSM2(private_key="",public_key="")
    temp=sm2_c._kg(inverse(d2,n),P1)
    G_1=generate_G_1(ecctable['g'])#-G
    P=sm2_c._add_point(temp,G_1)#两个点相加
    P=sm2_c._convert_jacb_to_nor(P)#得到最终的x||y
    return P

def generate_r_s2_s3(d2,Q1,e):
    n=int(ecctable['n'],16)
    sm2_c=sm2.CryptSM2(private_key="",public_key="")
    k2=generate_d2()
    Q2=sm2_c._kg(k2,ecctable['g'])
    k3=generate_d2()
    temp=sm2_c._kg(k3,Q1)
    P=sm2_c._add_point(temp,Q2)#两个点相加
    P=sm2_c._convert_jacb_to_nor(P)#得到最终的x||y
    x1=int(P[0:sm2_c.para_len],16)
    r=(x1+int(e.hex(),16))%n
    s2=(d2*k3)%n
    s3=d2*(r+k2)%n
    return(r,s2,s3)

#------------------test--------------



#建立TCP连接
HOST = ''
PORT = 50007
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((HOST, PORT))
s.listen(5)
print('Listening on port:',PORT)
conn, addr = s.accept()
print('Connected by', addr)

P1 = conn.recv(1024).decode('utf-8')#接受P1
print("接受的P1",P1)
d2=generate_d2()
P=generate_P(d2,P1)#产生公钥
print("产生的公钥为：",P)
conn.sendall("OK".encode("utf-8"))


Q1=conn.recv(1024).decode('utf-8')#接受Q1
print("接受到的Q1",Q1)
conn.sendall("OK".encode("utf-8"))

e=conn.recv(1024)#接受e
print("接受到的e",e)
conn.sendall("OK".encode("utf-8"))


r,s2,s3=generate_r_s2_s3(d2,Q1,e)#产生r,s2,s3并发送给另一个人

print("发送的r",r)
conn.sendall(hex(r)[2:].encode('utf-8'))
an=conn.recv(1024)
assert an.decode('utf-8')=="OK","fail1"

print("发送的s2",s2)
conn.sendall(hex(s2)[2:].encode('utf-8'))
an=conn.recv(1024)
assert an.decode('utf-8')=="OK","fail1"

print("发送的s3",s3)
conn.sendall(hex(s3)[2:].encode('utf-8'))
an=conn.recv(1024)
assert an.decode('utf-8')=="OK","fail1"