import base64
import binascii
import hmac
import hashlib 
from gmssl import sm2, func
#import pybitcointools
private_key = '00B9AB0B828FF68872F21A837FC303668428DEA11DCD1B24429D0C99E24EED83D5'
public_key = 'B9C9A6E04E9C91F7BA880429273747D7EF5DDEB0BB2FF6317EB00BEF331A83081A6994B8993F3F5D6EADDDB81872266C87C018FB4162F5AF347B483E24620207'
#n是sm2椭圆曲线的阶
n='FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123'

def HMAC_K(k,m):
    """
    k是密钥，m是消息，都是byte形式
    """
    h1 = hmac.new(k, m, hashlib.sha256).digest()
    return h1


def generate_k(msghash,x):
    """
    k是密钥，m是消息，都是byte形式
    """
    v = b'\x01' * 32
    k = b'\x00' * 32
    k=HMAC_K(k,v+b'\x00'+x+msghash)
    v = HMAC_K(k,v)
    k=HMAC_K(k,v+b'\x01'+x+msghash)
    v = HMAC_K(k,v)
    v = HMAC_K(k,v)
    while(int.from_bytes(v, byteorder='big')>=int.from_bytes(bytes.fromhex(n), byteorder='big')-1):
        k=HMAC_K(k,v+b'\x00')
        v=HMAC_K(k,v)
    return binascii.hexlify(v).decode("ascii")




def sm2_sign(m,public_key,private_key):
    """
    此处的m为byte
    """
    msghash=hashlib.sha256(m).digest()
    pri=bytes.fromhex(private_key)#私钥的byte形式
    k=generate_k(msghash,pri)#确定性签名算法得到k
    print("确定性签名算法产生的k：",k)
    sm2_crypt = sm2.CryptSM2(
    public_key=public_key, private_key=private_key)
    sign = sm2_crypt.sign(m, k) #  16进制
    return sign
    

def sm2_vertify(m,sign,public_key):
    sm2_crypt = sm2.CryptSM2(
    public_key=public_key,private_key='')#验证的时候不需要私钥，所以直接给一个空的
    return sm2_crypt.verify(sign,m )


#运行尝试
m=input("请输入需要签名的信息")

sign=sm2_sign(m.encode("utf-8"),public_key,private_key)#进行了签名
print("签名为r||s：",sign)
print("验证结果为：",sm2_vertify(m.encode("utf-8"),sign,public_key))#进行了验证







