""" MQTT Crypto container """

import sys
import json
import hashlib
import traceback
import binascii
import time
from datetime import datetime
import random

from Crypto.Cipher import DES3
from Crypto.Cipher import AES
from Crypto import Random

# pylint: disable=C0413
# pylint: disable=W0703
sys.path.append('../')
from mcrypt import rsa
from mcrypt import des3
from mcrypt import arc4
from mcrypt import aes
from mcrypt import salsa
from mcrypt import none

# pylint: disable=C0301
# pylint: disable=C0326
AVAILABLE_ALGORITHMS = {"NONE":  {"class":none.MQTTNONE,     "klen":["0"],                            "mode":{"NONE":"NONE"}},
                        "AES":   {"class":aes.MQTTAES,       "klen":["16", "24", "32"],               "mode":{"CFB":AES.MODE_CFB, "ECB":AES.MODE_ECB, "CBC":AES.MODE_CBC, "OFB":AES.MODE_OFB}},
                        "ARC4":  {"class":arc4.MQTTARC4,     "klen":["8", "16", "24", "32", "64"],    "mode":{"NONE":"NONE"}},
                        "DES3":  {"class":des3.MQTTDES3,     "klen":["16", "24"],                     "mode":{"CFB":DES3.MODE_CFB, "ECB":DES3.MODE_ECB, "CBC":DES3.MODE_CBC, "OFB":DES3.MODE_OFB}},
                        "SALSA": {"class":salsa.MQTTSALSA20, "klen":["32"],                           "mode":{"NONE":"NONE"}},
                        "RSA":   {"class":rsa.MQTTRSA,       "klen":["1024", "2048", "4096"],         "mode":{"NONE":"NONE"}}
                       }
class CRC32HASH(object):
    def __init__(self):
        self.hash = 0

    def update(self, value):
        self.hash = binascii.crc32(str(self.hash).encode()) + binascii.crc32(value)

    def hexdigest(self):
        return hex(self.hash)

AVAILABLE_MACS = {"NONE":None, "MD5": hashlib.md5, "SHA1": hashlib.sha1, "SHA224": hashlib.sha224, "SHA256":hashlib.sha256, "SHA384":hashlib.sha384, "SHA512":hashlib.sha512, "CRC32": CRC32HASH}

def local():
    """ Local time """
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

def gmt():
    """ GM time """
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())

def epoc():
    """ EPOC time """
    return str(int(time.time()))

def epocmod255():
    """ EPOC time wiht mod 255 """
    return str(int(time.time()%255))

AVAILABLE_TSTAMPS = {"NONE": None, "EPOC": epoc, r"EPOC%255":epocmod255, "Local y-m-d H:M:S": local, "GMT y-m-d H:M:S":gmt}

SEQODD_VALS = [1,4,8,2,3]

MSGSEQ = 0

# pylint: disable=W0603
def seqlin():
    """ Linear sequence """
    global MSGSEQ
    MSGSEQ = MSGSEQ + 1
    return (MSGSEQ - 1)%1024

def seqeven():
    """ Even sequence """
    global MSGSEQ
    MSGSEQ = MSGSEQ + 2 + (MSGSEQ % 2)
    return (MSGSEQ - 2)%1024

def seqodd():
    """ Odd sequence """
    global MSGSEQ
    MSGSEQ = MSGSEQ + 1
    return SEQODD_VALS[(MSGSEQ-1)%(len(SEQODD_VALS))]


AVAILABLE_SEQ = {"NONE": None, "0,1,2...":seqlin, "0,2,4...": seqeven, "1,4,8,2,3": seqodd}

# pylint: enable=W0603
# pylint: enable=C0301
# pylint: enable=C0326

def get_available_algorithms():
    """ Get available algorithms """
    ret = []
    for alg in AVAILABLE_ALGORITHMS:
        ret.append(alg)
    return ret

def get_available_macs():
    """ GET available macs """
    ret = []
    for mac in AVAILABLE_MACS:
        ret.append(mac)
    return ret

def get_available_rands():
    """ Get available random bytes amounts """
    ret = ["0", "1", "2", "4", "8", "16", "32", "64"]
    return ret

def get_available_seqs():
    """ Get available sequences """
    ret = []
    for seq in AVAILABLE_SEQ:
        ret.append(seq)
    return ret

def get_available_tstamp():
    """ Get available time stamps """
    ret = []
    for tstamp in AVAILABLE_TSTAMPS:
        ret.append(tstamp)
    return ret

class MCONT():
    """ Encrypt container """
    def __init__(self, alg, secret="TTKS0600"):
        self.secret = secret
        self.alg = None
        self.mode = None
        if alg is None:
            return #Destructing

        self.mqtt_path = {"Alg":"NONE", "Klen": "0", "Mode": "NONE"}
        alg = alg.upper()
        if alg in AVAILABLE_ALGORITHMS:
            self.alg = AVAILABLE_ALGORITHMS[alg]
            if "NONE" in self.alg["mode"]:
                self.mode = self.alg["mode"]["NONE"]
            else:
                self.mode = self.alg["mode"]["CBC"]
            self.klen = self.alg["klen"][0]
            self.mqtt_path["Alg"] = alg
        else:
            print("Invalid/unsupported algorithm " + str(self.alg))
            raise ValueError

    def get_key_len(self):
        """ Get key len """
        if self.alg:
            return self.alg["klen"]
        else:
            print("Invalid/unsupported algorithm " + self.mqtt_path["Alg"])
            raise ValueError
        return None

    def set_key_len(self, klen):
        """ Set key len """
        if self.alg:
            if klen in self.alg["klen"]:
                self.klen = int(klen)
                self.mqtt_path["Klen"] = klen
                return
        print("Invalid/unsupported key length " + klen + " for algorithm " + self.mqtt_path["Alg"])
        raise ValueError

    def get_modes(self):
        """ Get modes """
        if self.alg:
            return list(self.alg["mode"].keys())
        print("Invalid/unsupported algorithm " + self.mqtt_path["Alg"])
        raise ValueError

    def set_mode(self, mode):
        """ Set mode """
        if mode and self.alg:
            mode = mode.upper()
            if mode in self.alg["mode"]:
                self.mode = mode
                return

    def get_macs(self):
        """ Get macs """
        self = self
        return list(AVAILABLE_MACS.keys())

    def get_path(self):
        """ Get path / topic """
        return (r"TTKS0600/" + str(self.mqtt_path["Alg"]) +
                r"/" + str(self.klen) + r"/" + str(self.mode))

    # pylint: disable=R0912
    # pylint: disable=R0913
    # pylint: disable=R0914
    def construct(self, value, addmac="NONE", addrandom=0, mode=None,
                  tstamp=None, seq=None, rnddict=None, splitrandomnum=None):
        """ Cosntruct """
        data = {}
        data["D"] = value

        if mode:
            self.set_mode(mode)

        path = self.get_path()

        # Add requested amount of random bytes - either as one value or in single bytes
        if addrandom > 0:
            if splitrandomnum:
                ind = 0
                rndbytes = Random.get_random_bytes(int(addrandom))
                for i in rndbytes:
                    data[ind] = str(i)
                    ind += 1
            else:
                data["R"] = binascii.hexlify(Random.get_random_bytes(int(addrandom))).decode()

        # Add requested sequence number type
        if seq != None and seq != "NONE":
            data["S"] = str(AVAILABLE_SEQ[seq]())

        # Add reuqsted timestamp type
        if tstamp != None and tstamp != "NONE":
            if tstamp in AVAILABLE_TSTAMPS:
                data["T"] = AVAILABLE_TSTAMPS[tstamp]()

        start = time.time()

        #Randomize dict structure before encrytpion and hash count
        if rnddict:
            temp = data
            keys = list(temp.keys())
            random.shuffle(keys)
            data = {}
            for k in keys:
                data[k] = temp[k]

        # Count requested hash over payload and MQTT topic (path)
        if addmac != None and addmac != "NONE":
            if addmac.upper() in AVAILABLE_MACS:
                myhash = AVAILABLE_MACS[addmac.upper()]()
                myhash.update(path.encode())
                datak = list(data.keys())
                #print(datak)
                for k in datak:
                    myhash.update(data[k].encode())
                data["H"] = (addmac.upper(), myhash.hexdigest())

        ciphertext = None
        try:
            algo = self.alg["class"]
            chip = algo(secret=self.secret,
                        key_len=int(self.klen),
                        mode=self.alg["mode"][self.mode])
            ciphertext = chip.encrypt(json.dumps(data))

            duration = time.time() - start
        except Exception as failure:
            duration = -1
            #traceback.print_exc()
            raise failure

        return {"Path": path,
                "Plaintext": json.dumps(data),
                "Payload": {"D": value},
                "Ciphertext": ciphertext,
                "Duration": duration}

    # pylint: enable=R0912

    def destruct(self, ciphertext, path):
        """ Destruct """
        pathlst = path.split(r"/")

        if len(pathlst) == 4:
            if pathlst[0] != "TTKS0600":
                return

        algo = pathlst[1]
        klen = pathlst[2]
        mode = pathlst[3]

        self.__init__(algo, self.secret)
        self.set_mode(mode)
        self.set_key_len(klen)

        duration = -2
        try:
            algo = self.alg["class"]
            start = time.time()
            chip = algo(secret=self.secret,
                        key_len=self.klen,
                        mode=self.alg["mode"][self.mode])
            plaintext = chip.decrypt(ciphertext)

        except Exception as failure:
            print(failure)
            traceback.print_exc()
            raise ValueError

        data = json.loads(plaintext)

        if "H" in data:
            if data["H"][0].upper() in AVAILABLE_MACS:
                myhash = AVAILABLE_MACS[data["H"][0]]()
                myhash.update(path.encode())
                datak = list(data.keys())
                for akey in datak:
                    if akey != "H":
                        myhash.update(data[akey].encode())
                if data["H"][1] != myhash.hexdigest():
                    print("HASH missmatch")
                    print(data["H"])
                    print(myhash.hexdigest())
                    raise ValueError

        duration = time.time() - start
        return {"Path": path, "Plaintext": data, "Ciphertext": ciphertext, "Duration": duration}

def selftest(secret):
    """ Local tests """
    algs = get_available_algorithms()
    for alg in algs:
        cipher = MCONT(alg, secret)
        keylens = cipher.get_key_len()
        modes = cipher.get_modes()

        for keylen in keylens: # select key
            for mode in modes: # select mode
                cipher.set_key_len(keylen)
                cipher.set_mode(mode)
                cipher.construct("OK")

# pylint: disable=R0913
# pylint: disable=R0914
def test_run(alg):
    """ Local tests """
    cipher = MCONT(alg)
    keylens = cipher.get_key_len()
    modes = cipher.get_modes()
    hashs = cipher.get_macs()

    passed = 0
    fsum = []
    cnt = 0
    # pylint: disable=R1702
    for keylen in keylens: # select key
        for mode in modes: # select mode
            for hss in hashs: # select hash algorithm
                for rnd in [0, 1, 2, 4, 8, 16]: # Bytes in random number part
                    #aes  32   CFB   SHA22416 PLen:6    CLen:128
                    output = alg.ljust(6) + keylen.ljust(5) + mode.ljust(6) + \
                             hss.ljust(8) + str(rnd).ljust(5)
                    try:
                        #encrypt
                        cipher = MCONT(alg)
                        cipher.set_key_len(keylen)
                        cipher.set_mode(mode)
                        cipherjunk = cipher.construct(str(cnt*1000), hss, rnd)
                        #pprint(cipherjunk)
                        output = output + "PLen:" + str(len(cipherjunk["Plaintext"])).ljust(5) + \
                                 "  CLen:" + str(len(cipherjunk["Ciphertext"])).ljust(5)

                        #decrypt
                        cipher = MCONT(None)
                        plainjunk = cipher.destruct(cipherjunk["Ciphertext"], cipherjunk["Path"])
                        encnt = int(plainjunk["Plaintext"]["D"])/1000
                        if cnt != encnt:
                            output = output + ("FAILED in> " + str(cnt) + " >out " +str(encnt))
                            fsum.append(output)
                        else:
                            passed = passed + 1
                        print(output)
                    except Exception as failure:
                        var = traceback.format_exc()
                        fsum.append(output + "\t" + str(failure) + "\t" + str(var))
                        print(output + "\t" + str(failure))
                    cnt = cnt + 1
    return ([cnt, passed], fsum)
    # pylint: enable=R1702

def test_all():
    """ Local tests """
    # pylint: disable=C0103
    (ca, pa) = test_run("aes")
    (cb, pb) = test_run("rsa")
    (cc, pc) = test_run("arc4")
    (cd, pd) = test_run("des3")
    (ce, pe) = test_run("salsa")

    print("Cases " + str(ca[0] + cb[0] + cc[0] + cd[0] + ce[0]) +
          " passed " + str(ca[1] + cb[1] + cc[1] + cd[1] + ce[1]))

    for failure in pa + pb + pc + pd + pe:
        print(failure)
    # pylint: enable=C0103

def single_tests(intxt, alg, mode, klen, myhash="NONE", rnd=0):
    """ Local tests """
    tase = MCONT(alg)
    tase.set_mode(mode)
    tase.set_key_len(klen)
    cipherjunk = tase.construct(intxt, myhash, rnd)

    cipher = MCONT(None)
    plainjunk = cipher.destruct(cipherjunk["Ciphertext"], cipherjunk["Path"])
    plaintext = plainjunk["Plaintext"]["D"]

    if plaintext == intxt:
        print("OK\t")# + str(cipherjunk) + "\t" + str(plaintext))
    else:
        print("FAIL\t")# + intxt + " " + plaintext + "\t" + str(cipherjunk) + "\t" + str(plaintext))

def test_all_singles():
    """ Local tests """
    # pylint: disable=C0326
    single_tests("hello world how things are going?", "AES",   "CBC",  "32")
    single_tests("hello world how things are going?", "DES3",  "OFB",  "24")
    single_tests("hello world how things are going?", "RSA",   "NONE", "4096")
    single_tests("hello world how things are going?", "ARC4",  "NONE", "16")
    single_tests("hello world how things are going?", "SALSA", "NONE", "32")
    single_tests("hello world how things are going?", "AES",   "CBC",  "32",  "SHA256", 2)
    single_tests("hello world how things are going?", "DES3",  "OFB",  "24",  "SHA256", 2)
    single_tests("hello world how things are going?", "RSA",   "NONE", "4096","SHA256", 2)
    single_tests("hello world how things are going?", "ARC4",  "NONE", "16",  "SHA256", 2)
    single_tests("hello world how things are going?", "SALSA", "NONE", "32",  "SHA256", 2)
    # pylint: enable=C0326

if __name__ == "__main__":
    test_all_singles()
    test_all()
