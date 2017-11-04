""" ARC4 """
# error: Microsoft Visual C++ 9.0 is required. Get it from http://aka.ms/vcpython27
import sys
from time import time
import traceback
import binascii
import hexdump

from Crypto.Cipher import ARC4
from Crypto import Random

#pylint: disable=C0413
sys.path.append('../')
from mfile import mfile

class MQTTARC4():
    """ ARC4 """
    def __init__(self, secret, key_len=32, mode=None):
        self.local_secrets = mfile.LocalSecrets(secret)
        self.prikey = None
        mode = mode
        sc_tuple = self.local_secrets.read("ARC4", str(key_len))
        if sc_tuple is None:
            try:
                key = binascii.hexlify(Random.get_random_bytes(int(key_len/2))).rjust(key_len)
                self.local_secrets.write(key, None, "ARC4", str(key_len))
                sc_tuple = self.local_secrets.read("ARC4", str(key_len))
            except Exception as failure:
                print(failure)
                traceback.print_exc()
                raise failure

        if sc_tuple:
            self.prikey = sc_tuple[0]
        else:
            raise ValueError

    def encrypt(self, plaintext):
        """ Encrypt """
        cipher = ARC4.new(self.prikey)
        cipher_text = cipher.encrypt(plaintext.encode("utf-8"))
        return cipher_text

    def decrypt(self, ciphertext):
        """ Decrypt """
        cipher = ARC4.new(self.prikey)
        return cipher.decrypt(ciphertext).decode("utf-8")

def test(loops=10, key_len=32):
    """ local tests """
    print("ARC4 test")
    plaintext_org = str(23.5)

    for index in range(0, loops):
        encround = MQTTARC4("TTKS0600", key_len)
        start = time()
        ciphertext = encround.encrypt(plaintext_org)

        print("Encrypted " + " " + str(len(ciphertext)) +
              " in " + str(round((time()-start), 5)) +
              "\t" + hexdump.dump(ciphertext, size=2, sep=' '))
        start = time()
        plaintext = encround.decrypt(ciphertext)
        print("Decrypted " + " " + str(len(plaintext)) +
              " in " + str(round((time()-start), 5)) +
              "\t" + hexdump.dump(plaintext.encode(), size=2, sep=' '))
        if plaintext != plaintext_org:
            print("FAILED")
            print("\t" + str(plaintext_org))
            print("\t" + str(plaintext))
        index = index

if __name__ == "__main__":
    test(key_len=8)
    test(key_len=16)
    test(key_len=32)
    test(key_len=64)
