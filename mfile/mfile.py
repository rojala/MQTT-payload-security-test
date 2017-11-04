""" Handle local key file """
import hashlib
import os
import inspect
import pickle
from Crypto.Cipher import AES

class LocalSecrets():
    """ Handle key file = local secrets """
    def __init__(self, secret="TTKS0600", filename="secrets.bin", iv="jamk", force_new=False):
        """ All the secrets will be here.... """
        if secret is None:
            raise ValueError
        self.filename = filename
        self.key_len = 24
        self.prikey = secret[:self.key_len].rjust(self.key_len).encode()
        secret = 0
        self.init_vector = iv[:AES.block_size].rjust(AES.block_size).encode()
        self.mode = AES.MODE_CBC
        self.myfile = os.path.abspath(inspect.getfile(inspect.currentframe()))
        self.keepinsafe = True

        # Remove exising file if new forsed to be used
        if os.path.isfile(self.filename) and force_new:
            os.unlink(self.filename)

    def __aes__encrypt__(self, plaintext, usepw=None):
        key = self.prikey
        if usepw:
            key = usepw
        cipher = AES.new(key, self.mode, self.init_vector)
        pl_len = len(plaintext) + (AES.block_size - (len(plaintext) % AES.block_size))
        ciphertext = cipher.encrypt(plaintext.ljust(pl_len))
        return ciphertext

    def __aes__decrypt__(self, ciphertext, usepw=None):
        key = self.prikey
        if usepw:
            key = usepw
        cipher = AES.new(key, self.mode, self.init_vector)
        plaintext = cipher.decrypt(ciphertext)
        return plaintext

    def __read__(self):
        """ Read file and return content """
        content = None
        try:
            content = self.__read_from_file__()
            myhash = hashlib.sha512()
            myhash.update(str(content[1]).encode())
            #myhash.update(self.myfile.encode()) add later if feasible
            if content[0] != myhash.hexdigest():
                print("8<-8<-8< Hash mismatch 8<-8<-8< ")
                print(myhash.hexdigest())
                print(content[0])
                print(">8->8->8 Hash mismatch >8->8->8 ")
                raise IOError
            content = content[1]

        except IOError:
            #File does not exists, create new one
            return None
        except ValueError:
            #File corrupted, create new one
            return None

        except pickle.UnpicklingError:
            return None

        return content

    def __read_from_file__(self):
        """ Read file """
        with open(self.filename, mode='rb') as read_fb:
            ciphertext = read_fb.read()
        if self.keepinsafe:
            plaintext = self.__aes__decrypt__(ciphertext)
        else:
            plaintext = ciphertext
        content = pickle.loads(plaintext)
        return content

    def __write_to_file__(self, data, usepw):
        """ Write file """
        if self.keepinsafe:
            ciphertext = self.__aes__encrypt__(data, usepw)
        else:
            ciphertext = data

        if usepw:
            return ciphertext
        with open(self.filename, mode='wb') as write_fb:
            write_fb.write(ciphertext)

    def __write__(self, file_content_dict, usepw=None):
        """ Write complete file """
        output = [0, file_content_dict]
        myhash = hashlib.sha512()
        myhash.update(str(file_content_dict).encode())
        #hs.update(self.myfile.encode()) #add later if feasible
        myhash.hexdigest()
        output[0] = myhash.hexdigest()
        output = pickle.dumps(output)
        return self.__write_to_file__(output, usepw)

    def read(self, alg, alg_type):
        """ read specific algoritm from file """
        data = self.__read__()
        keyword = self.__get_kw__(alg, alg_type)
        if data != None and keyword in data:
            return data[keyword]
        print("mfile: " + alg + " " + alg_type + " Not found")
        return None

    def __get_kw__(self, alg, alg_type):
        """ Form keyword """
        self = self
        return alg + "_" + alg_type

    def write(self, pri, pub, alg, alg_type):
        """ write specific algorithm to file """
        #Read complete file and and if file does not exists create empty content
        conent = self.__read__()
        if conent is None:
            conent = {}

        # create new/update existing entry
        conent[self.__get_kw__(alg, alg_type)] = (pri, pub)
        self.__write__(conent)

    def update(self, file_content, usepw=None):
        """ Update all entries... """
        #Read complete file and and if file does not exists create empty content
        content = self.__read__()
        if content is None:
            content = {}

        for a_content in file_content:
            content[a_content] = file_content[a_content]

        #write file back
        return self.__write__(content, usepw)

def test():
    """ local tests """
    ls_fp = LocalSecrets()
    ls_fp.__write__(['eka', {"a":12334423, "b":"asf"}, 'toka', 'kolmas'])
    print(ls_fp.__read__())
    print(ls_fp.__read__())


if __name__ == "__main__":
    test()
