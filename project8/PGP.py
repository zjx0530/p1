from gmssl import sm2 ,sm4
import sys
import random 

str36="1234567890qwertyuiopasdfghjklzxcvbnm"
iv = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

#以下均是接受者的密钥
private_key= '00B9AB0B828FF68872F21A837FC303668428DEA11DCD1B24429D0C99E24EED83D5'
public_key = 'B9C9A6E04E9C91F7BA880429273747D7EF5DDEB0BB2FF6317EB00BEF331A83081A6994B8993F3F5D6EADDDB81872266C87C018FB4162F5AF347B483E24620207'



def generate_random_k():
    """
    生成随机的k
    """
    str=""
    for i in range(0,16):
        str+=str36[random.randint(0,35)]
    return str.encode('utf-8')

def sender(m):
    K=generate_random_k()#生成一个随机的k

    crypt_sm4 = sm4.CryptSM4()#布置sm4堆成加密器
    crypt_sm4.set_key(K, sm4.SM4_ENCRYPT)
    encrypt_m = crypt_sm4.crypt_ecb(m.encode("utf-8")) #得到消息加密
    
    sm2_crypt = sm2.CryptSM2(public_key=public_key, private_key="")#布置sm2加密
    enc_k = sm2_crypt.encrypt(K)#得到密钥加密
    return (encrypt_m,enc_k)


def receiver(encrypt_m,enc_k):
    """
    得到发送者发来的加密的消息和密钥之后
    先解密得到密钥，然后再解密消息
    """
    sm2_crypt = sm2.CryptSM2(public_key=public_key, private_key=private_key)#布置sm2加密
    K=sm2_crypt.decrypt(enc_k)
    crypt_sm4 = sm4.CryptSM4()#布置sm4堆成加密器
    crypt_sm4.set_key(K, sm4.SM4_DECRYPT)
    decrypt_m = crypt_sm4.crypt_ecb(encrypt_m)
    return decrypt_m.decode("utf-8")#返回解密的消息


#---------------------test---------------------------

m=input("请输入你想要加密的数据:")

encrypt_m,enc_k=sender(m)
print("加密后的消息为：",encrypt_m)
print("加密后的会话秘钥为：",enc_k)

dec_m=receiver(encrypt_m,enc_k)

print("解密之后的消息",dec_m)