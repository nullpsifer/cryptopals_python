import itertools
import os
from random import SystemRandom
from time import sleep
from utils.aesutils import AES, isECB


class SimpleInputECB:

    def __init__(self,input :bytes):
        self.plaintext = input
        aes = AES(randomkey(),'ECB')
        self.encrypt = aes.encrypt

    def oracle(self, attackinput :bytes):
        sleep(0.02)
        return self.encrypt(attackinput+self.plaintext)


class ExampleECBCBCOracle:

    def __init__(self):
        self.gen = SystemRandom()
        self.isECB = 'ECB' if self.gen.randint(0,1) else 'CBC'
        self.cipher = AES(randomkey(),self.isECB)

    def oracle(self,plaintext :str):
        return self.cipher.encrypt(os.urandom(self.gen.randint(5,10))+plaintext.encode('utf-8')+os.urandom(self.gen.randint(5,10)))


class ECBOrCBC:

    def __init__(self, oracle,blocksize=16):
        self.blocksize = blocksize
        self.oracle = oracle

    def test(self):
        ciphertext = self.oracle('A'*(self.blocksize*3))
        return 'ECB' if isECB(ciphertext) else 'CBC'


def randomkey(blocksize=16):
    return os.urandom(blocksize)

class ECBCutAndPasteTest:

    #id_iter = itertools.count().__next__
    def __init__(self,email :bytes, role='user'):
        self.cipher = AES(randomkey(),'ECB')
        self.profile = {'uid': 10,
                        'email': email,
                        'role':role}

    def encodedprofile(self):
        return b'email='+self.profile["email"]+f'&uid={self.profile["uid"]}&role={self.profile["role"]}'.encode('utf-8')

    def profile_for(self,newemail)-> None:
        self.profile['email'] = newemail.replace('&','').replace('=','')

    def parseencodedstring(self,encodedstring):
        for kvp in encodedstring.split('&'):
            key,value = kvp.split('=')
            if key in self.profile.keys():
                self.profile[key] = value.encode('utf-8') if key == 'email' else value

    def encryptprofile(self):
        return self.cipher.encrypt(self.encodedprofile())

    def decryptencryptedprofile(self,ctext):
        self.parseencodedstring(self.cipher.decrypt(ctext).decode('utf-8'))

