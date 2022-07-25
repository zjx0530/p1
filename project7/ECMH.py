from gmssl import sm2
from hashlib import sha256
import binascii
#圆锥曲线的参数
ecctable = {
    'n': 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123',
    'p': 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF',
    'g': '32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7'\
         'bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0',
    'a': 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC',
    'b': '28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93',
}


def ECMH(m):
    """
    返回了m的hash对应的椭圆曲线上的点的x坐标和y坐标16进制的字符串拼接,即x||y
    考虑到知道了y计算x相对简单，因此直接以x作为最终的hash值
    m为字符串
    """
    hash_256=sha256(str(m).encode()).digest()
    while(int(hash_256.hex(),16)>=int(ecctable['n'],16)):#为了让这个值处于（0，n-1）之间，如果大了就加盐
        hash_256=sha256(b'\x00'+hash_256)
    pri=int(hash_256.hex(),16)
    sm2_c=sm2.CryptSM2(private_key="",public_key="")#因为只是利用其中函数所以不设置公钥私钥
    P1=sm2_c._kg(pri,ecctable['g'])#此处计算了哈希值*G后点的坐标x||y
    return P1
 
def ECMH_append(h,m):
    """
    为ECMH后的hash值添加新的元素后形成hash
    其中m为字符串
    """
    hash_256=sha256(str(m).encode()).digest()
    while(int(hash_256.hex(),16)>=int(ecctable['n'],16)):#为了让这个值处于（0，n-1）之间，如果大了就加盐
        hash_256=sha256(b'\x00'+hash_256)
    sm2_c=sm2.CryptSM2(private_key="",public_key="")
    pri=int(hash_256.hex(),16)
    P1=sm2_c._kg(pri,ecctable['g'])#得到后来添加的字符串的哈希值对应的坐标
    P=sm2_c._add_point(P1,h)#两个点相加
    P=sm2_c._convert_jacb_to_nor(P)#得到最终的x||y
    return P


#----------------------test-----------------------------------------------

p1=input("请输入你想hash的第一个字符串：")
p2=input("请输入你想hash的第二个字符串：")
h1=ECMH(p1)
h2=ECMH(p2)
print("第一个字符串hash值",h1)
print("第二个字符串hash值",h2)
print("先hash第一个字符串再添加第二个：",ECMH_append(h1,p2))
print("先hash第二个字符串再添加第一个：",ECMH_append(h2,p1))




