# pyclean .
import sys
sys.path.append('../')

from mcrypt import rsa
from mcrypt import des3
from mcrypt import arc4
from mcrypt import aes
from mcrypt import salsa

from Crypto.Cipher import DES3
from Crypto.Cipher import AES

def basic_encryption_test():
    print("********** RSA **********")
    rsa.test()

    print("********** DES **********")
    des3.test(4, mode=DES3.MODE_CFB, key_len=16) #16 = DES
    des3.test(4, mode=DES3.MODE_CFB, key_len=24) #24 = 3DES
    des3.test(4, mode=DES3.MODE_ECB, key_len=16)
    des3.test(4, mode=DES3.MODE_ECB, key_len=24)
    des3.test(4, mode=DES3.MODE_CBC, key_len=16)
    des3.test(4, mode=DES3.MODE_CBC, key_len=24)
    des3.test(4, mode=DES3.MODE_OFB, key_len=16)
    des3.test(4, mode=DES3.MODE_OFB, key_len=24)
    #des3.test(4, mode=DES3.MODE_CTR, key_len=16) #require counter.... not implemented
    #des3.test(10,DES3.MODE_CTR, key=24)
    #des3.test(10,DES3.MODE_OPENPGP, key_len=16) #decrypt failed...
    #des3.test(10,DES3.MODE_OPENPGP, key_len=24)

    print("********** ARC4 **********")
    arc4.test(2)

    print("********** AES **********")
    aes.test(4, mode=AES.MODE_CFB, key_len=16) #AES128
    aes.test(4, mode=AES.MODE_CFB, key_len=24) #24 = #AES196
    aes.test(4, mode=AES.MODE_CFB, key_len=32) #32 = #AES256
    aes.test(4, mode=AES.MODE_ECB, key_len=16)
    aes.test(4, mode=AES.MODE_ECB, key_len=24)
    aes.test(4, mode=AES.MODE_ECB, key_len=32)
    aes.test(4, mode=AES.MODE_CBC, key_len=16)
    aes.test(4, mode=AES.MODE_CBC, key_len=24)
    aes.test(4, mode=AES.MODE_CBC, key_len=32)
    aes.test(4, mode=AES.MODE_OFB, key_len=16)
    aes.test(4, mode=AES.MODE_OFB, key_len=24)
    aes.test(4, mode=AES.MODE_OFB, key_len=32)

    print("********** Salsa20 **********") #https://github.com/keybase/python-salsa20
    #salsa.test(2)

basic_encryption_test()