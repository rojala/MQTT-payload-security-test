""" RSA """
# https://www.laurentluce.com/posts/python-and-cryptography-with-pycrypto/

import sys
import traceback
from time import time
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
sys.path.append('../')
# pylint: disable=C0413
from mfile import mfile

class MQTTRSA():
    """ RSA """
    def __init__(self, secret, key_len, mode=None):
        self.pubkey = None
        self.prikey = None
        self.key_len = key_len
        mode = mode

        self.localsecrets = mfile.LocalSecrets(secret)

        sc_tuple = self.localsecrets.read("RSA", str(key_len))

        if sc_tuple is None:
            try:
                key = RSA.generate(key_len)
                # https://www.dlitz.net/software/pycrypto/api/current/Crypto.PublicKey.RSA-module.html
                # https://www.dlitz.net/software/pycrypto/api/current/Crypto.PublicKey.RSA-module.html
                prikey = key.exportKey('PEM')
                pubkey = key.publickey().exportKey('PEM')
                self.localsecrets.write(prikey, pubkey, "RSA", str(key_len))
                sc_tuple = self.localsecrets.read("RSA", str(key_len))

            except Exception as failure:
                print(failure)
                traceback.print_exc()
                raise failure
        if sc_tuple:
            self.pubkey = RSA.importKey(sc_tuple[1])
            self.prikey = RSA.importKey(sc_tuple[0])
        else:
            raise ValueError

    def encrypt(self, data):
        """ Encrypt """
        #if (self.key_len/8) < (len(data)-2):
        #    raise ValueError

        cipher_rsa = PKCS1_OAEP.new(self.pubkey)
        ciphertext = cipher_rsa.encrypt(data.encode("utf-8"))
        return ciphertext

    def decrypt(self, ciphertext):
        """ Decrypt """
        cipher_rsa = PKCS1_OAEP.new(self.prikey)
        plaintext = cipher_rsa.decrypt(ciphertext).decode()
        return plaintext

def test(loops=10):
    """ Local tests """
    plaintext_org = "21.3"
    if loops > 10:
        loops = 10
    for keymultip in range(1, loops):
        encrnd = MQTTRSA("TTKS0600", 1024*keymultip)
        start = time()
        ciphertext = encrnd.encrypt(plaintext_org)
        print("Encrypted " + str(1024*keymultip) + " " +
              str(len(ciphertext)).ljust(5) + " in " +
              str(round((time()-start), 4)).ljust(6))
        start = time()
        plaintext = encrnd.decrypt(ciphertext)
        print("Decrypted " + str(1024*keymultip) + " " +
              str(len(plaintext)).ljust(5) + " in " +
              str(round((time()-start), 4)).ljust(6))

        if plaintext != plaintext:
            print("FAILED")
            print("\t" + str(plaintext_org))
            print("\t" + str(plaintext))

if __name__ == "__main__":
    test()
