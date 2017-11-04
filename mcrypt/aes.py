""" AES """
# error: Microsoft Visual C++ 9.0 is required. Get it from http://aka.ms/vcpython27

import sys
import binascii
import traceback
from time import time
import hexdump
from Crypto.Cipher import AES
from Crypto import Random

#pylint: disable=C0413
sys.path.append('../')
from mfile import mfile

class MQTTAES():
    """ AES Class """
    def __init__(self, secret, key_len, mode=AES.MODE_CBC):
        self.localsecrets = mfile.LocalSecrets(secret)
        self.mode = mode
        self.prikey = None
        ok_key_len = [16, 24, 32]
        if key_len not in ok_key_len:
            print("Key len must be 16/128, 24/196, 32/256 - not " + str(key_len))
            raise ValueError

        sc_tuple = self.localsecrets.read("AES", str(key_len))

        if sc_tuple is None:
            try:
                init_vector = binascii.hexlify(Random.get_random_bytes(
                    int(AES.block_size/2))).rjust(AES.block_size)

                key = binascii.hexlify(Random.get_random_bytes(int(key_len/2))).rjust(key_len)
                self.localsecrets.write(key, init_vector, "AES", str(key_len))
                sc_tuple = self.localsecrets.read("AES", str(key_len))
            except Exception as failure:
                print(failure)
                traceback.print_exc()
                raise failure
        if sc_tuple:
            self.prikey = sc_tuple[0]
            self.init_vector = sc_tuple[1]
        else:
            raise ValueError

    def encrypt(self, plaintext):
        """ Encrypt """
        plaintext = plaintext.encode("utf-8")
        if self.mode == AES.MODE_ECB:
            cipher = AES.new(self.prikey, self.mode)
        else:
            cipher = AES.new(self.prikey, self.mode, self.init_vector)
        plain_len = len(plaintext) + (AES.block_size - (len(plaintext) % AES.block_size))
        ciphertext = cipher.encrypt(plaintext.ljust(plain_len))
        return bytes(ciphertext)

    def decrypt(self, ciphertext):
        """ Decrypt """
        if self.mode == AES.MODE_ECB:
            cipher = AES.new(self.prikey, self.mode)
        else:
            cipher = AES.new(self.prikey, self.mode, self.init_vector)
        plaintext = cipher.decrypt(ciphertext)
        return plaintext

def test(loops=10, mode=AES.MODE_CBC, key_len=24):
    """ local tests """
    print("AES test")
    org_plaintext = str(23.5)

    for index in range(1, loops):
        enround = MQTTAES(secret="TTKS0600", key_len=key_len, mode=mode)
        start = time()
        ciphertext = enround.encrypt(org_plaintext)

        print("Encrypted " + str(key_len*8) + " " +
              " mode:" +str(mode) + " " + str(len(ciphertext)) +
              " in " + str(round((time()-start), 5)).ljust(6) +
              "\t" + hexdump.dump(ciphertext, size=2, sep=' '))
        start = time()
        plaintext = enround.decrypt(ciphertext)
        print("Decrypted " + str(key_len*8) + " " +
              " mode:" +str(mode) + " " + str(len(plaintext)) +
              " in " + str(round((time()-start), 5)).ljust(6) +
              "\t" + hexdump.dump(plaintext, size=2, sep=' '))

        if float(plaintext) != float(org_plaintext):
            print("FAILED")
            print("\t" + str(org_plaintext))
            print("\t" + str(plaintext))
        index = index

if __name__ == "__main__":
    test(key_len=16)
    test(key_len=24)
    test(key_len=32)
