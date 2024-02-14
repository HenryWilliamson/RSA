
from Crypto.PublicKey  import RSA
from Crypto.Cipher import PKCS1_OAEP
import binascii
import math


text = ("7da8ffed704d231c7d8e26a61bf2da342b7e22bf1652f032588b301fb05ace8194ac1a6e82958bfd27fc653de572d6418ab8e92ff2ff82f89ca036fdad87ab5846c9c58d43e1659764db80f9057b3f6bb51faf9e96fd87dfb60a5d74e54b4f0049fd920d013d034e3677ed8f2ecd06be22825db4d395e1418b4fa9f490dd60f3")

publicKey = """-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCIDHP5EkMPaQ3FDL9yoHMREia5
WiTin3D2rwFvcCDc+AuVm0HiywEQQF8ZxOO4hEfvmXzVqPSojkkarDNqe8hQvsGx
lv/EjvL6ULf60Yt5BrlbLKnpkhcYSj0YRBf24lzQD8D2vzNlaW16aJXbwUzdaHN/
jUczApfsrMtkeVrirwIDAQAB
-----END PUBLIC KEY-----"""

key = RSA.importKey(publicKey)

e = key.e
n = key.n

def factor(n):
    a = math.isqrt(n) + 1
    while True:
        b2 = a * a - n
        b = math.isqrt(b2)
        if b * b == b2:
            p = a + b
            q = a - b
            return p, q
        a += 1

p, q = factor(n)

d = pow(key.e, -1, (p-1)*(q-1))
privateKey = pow(n, e, d)
byteText = binascii.unhexlify(text)
privateKey = PKCS1_OAEP.new(privateKey)
decryptedText = privateKey.decrypt(byteText)
print(decryptedText)