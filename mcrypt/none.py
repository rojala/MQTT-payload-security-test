""" None """

class MQTTNONE():
    """ NONE """
    def __init__(self, secret=None, key_len=None, mode=None):
        self.prikey = None
        secret = secret
        key_len = key_len
        mode = mode

    def encrypt(self, plaintext):
        """ Encrypt """
        self = self
        return bytes(str(plaintext).encode())

    def decrypt(self, ciphertext):
        """ Decrypt """
        self = self
        return ciphertext
