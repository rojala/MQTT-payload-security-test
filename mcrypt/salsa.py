""" SALSA 20 """
# https://github.com/keybase/python-salsa20
# https://www.crypto101.io/
import sys
import traceback
from time import time
import binascii
import hexdump
from Crypto import Random
from salsa20 import XSalsa20_xor
sys.path.append('../')
# pylint: disable=C0413
from mfile import mfile

class MQTTSALSA20():
    """ SALSA 20 """
    def __init__(self, secret, key_len=32, mode=None):
        self.localsecrets = mfile.LocalSecrets(secret)
        self.prikey = None
        self.init_vector = None
        mode = mode
        sc_tuple = self.localsecrets.read("SALSA20", str(key_len))

        if sc_tuple is None:
            try:
                init_vector = binascii.hexlify(
                    Random.get_random_bytes(int(24/2))).rjust(24).decode()
                key = binascii.hexlify(
                    Random.get_random_bytes(int(key_len/2))).rjust(key_len).decode()

                self.localsecrets.write(key, init_vector, "SALSA20", str(key_len))
                sc_tuple = self.localsecrets.read("SALSA20", str(key_len))

            except Exception as failure:
                print(failure)
                traceback.print_exc()
                raise failure

        if sc_tuple:
            self.prikey = sc_tuple[0].encode('utf-8')
            self.init_vector = sc_tuple[1].encode('utf-8')
        else:
            raise ValueError

    def encrypt(self, plaintext):
        """ Encrypt """
        cipher_text = XSalsa20_xor(plaintext.encode('utf-8'), self.init_vector, self.prikey)
        return cipher_text

    def decrypt(self, ciphertext):
        """ Decrypt """
        self = self
        return XSalsa20_xor(ciphertext, self.init_vector, self.prikey).decode()

def test(loops=10):
    """ local tests """
    print("SALSA20 test")
    plaintext_org = str(23.5)

    for index in range(0, loops):
        cipher = MQTTSALSA20(secret="TTKS0600")
        start = time()
        ciphertext = cipher.encrypt(plaintext_org)

        print("Encrypted " + " " + str(len(ciphertext)) + " in " +
              str(round((time()-start), 5)).ljust(4) + "\t" +
              hexdump.dump(ciphertext, size=2, sep=' '))
        start = time()
        plaintext = cipher.decrypt(ciphertext)
        print("Decrypted " + " " + str(len(plaintext)) + " in " +
              str(round((time()-start), 5)).ljust(6) + "\t" +
              hexdump.dump(plaintext.encode(), size=2, sep=' '))

        if plaintext != plaintext_org:
            print("FAILED")
            print("\t" + str(plaintext_org))
            print("\t" + str(plaintext))
        index = index

if __name__ == "__main__":
    test()
