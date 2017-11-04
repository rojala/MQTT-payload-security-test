""" DES and 3DES """

import sys
import traceback
from time import time
import binascii
import hexdump

from Crypto.Cipher import DES3
from Crypto import Random

#pylint: disable=C0413
sys.path.append('../')
from mfile import mfile

class MQTTDES3():
    """ DES and 3DES """
    def __init__(self, secret, key_len, mode=DES3.MODE_CBC):
        self.local_secrets = mfile.LocalSecrets(secret)
        self.mode = mode
        self.prikey = None
        if not (key_len == 16 or key_len == 24):
            print("Key len must be 16/128 or 24/196")
            raise ValueError

        sc_tuble = self.local_secrets.read("DES3", str(key_len))

        if sc_tuble is None:
            try:
                init_vect = binascii.hexlify(Random.get_random_bytes(
                    int(DES3.block_size/2))).rjust(DES3.block_size)
                key = binascii.hexlify(Random.get_random_bytes(int(key_len/2))).rjust(key_len)
                self.local_secrets.write(key, init_vect, "DES3", str(key_len))
                sc_tuble = self.local_secrets.read("DES3", str(key_len))
            except Exception as failure:
                print(failure)
                traceback.print_exc()
                raise failure

        if sc_tuble:
            self.prikey = sc_tuble[0]
            self.init_vect = sc_tuble[1]
        else:
            raise ValueError

    def encrypt(self, plaintext):
        """ Encrypt """
        plaintext = plaintext.encode('utf-8')

        if self.mode == DES3.MODE_ECB:
            cipher = DES3.new(self.prikey, self.mode)
        else:
            cipher = DES3.new(self.prikey, self.mode, self.init_vect)
        plain_len = len(plaintext) + (DES3.block_size - (len(plaintext) % DES3.block_size))
        ciphertext = cipher.encrypt(plaintext.ljust(plain_len))
        return bytes(ciphertext)

    def decrypt(self, ciphertext):
        """ Decrypt """
        if self.mode == DES3.MODE_ECB:
            cipher = DES3.new(self.prikey, self.mode)
        else:
            cipher = DES3.new(self.prikey, self.mode, self.init_vect)
        plaintext = cipher.decrypt(ciphertext)
        return plaintext.decode('utf-8')

def test(loops=10, mode=DES3.MODE_CFB, key_len=24):
    """ Local tests """
    print("3DES test")
    plaintext_org = str(23.5)

    for index in range(1, loops):
        encrnd = MQTTDES3(secret="TTKS0600", key_len=key_len, mode=mode)
        start = time()
        cihpertext = encrnd.encrypt(plaintext_org)

        print("Encrypted " + str(key_len*8) + " " +
              " mode:" +str(mode) + " " + str(len(cihpertext)) +
              " in " + str(round((time()-start), 5)).ljust(6) +
              "\t" + hexdump.dump(cihpertext, size=2, sep=' '))
        start = time()
        plaintext = encrnd.decrypt(cihpertext)
        print("Decrypted " + str(key_len*8) + " " +
              " mode:" +str(mode) + " " + str(len(plaintext)) +
              " in " + str(round((time()-start), 5)).ljust(6) +
              "\t" + hexdump.dump(plaintext.encode(), size=2, sep=' '))

        if float(plaintext) != float(plaintext_org):
            print("FAILED")
            print("\t" + str(plaintext_org))
            print("\t" + str(plaintext))
        index = index

if __name__ == "__main__":
    test(key_len=16)
    test(key_len=24)
    test(mode=DES3.MODE_CBC, key_len=16)
    test(mode=DES3.MODE_CBC, key_len=24)
