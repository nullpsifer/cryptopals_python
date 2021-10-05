import base64
from base64 import b16decode, b16encode
from Crypto.Cipher import AES as pycryptoAES
import os
import string
from tqdm import trange
from utils.binutils import BinUtils
from utils.pkcs7 import PKCS7

class AES:
     iv: str
     blocksize = 16
     padding = PKCS7(blocksize)
     def __init__(self,key :bytes,mode :str,iv=None):
          self.cipher = pycryptoAES.new(key,pycryptoAES.MODE_ECB)
          self.mode = mode
          if iv:
               self.iv = iv

     def encrypt(self,plaintext:bytes,iv=None):
         if self.mode == 'ECB':
              return b16encode(self.cipher.encrypt(self.padding.pad(plaintext))).decode('utf-8')
         if self.mode == 'CBC':
              ciphertext = ''
              if not iv:
                  self.iv = b16encode(os.urandom(self.blocksize)).decode('utf-8')
              paddedplaintext = b16encode(self.padding.pad(plaintext)).decode('utf-8')
              blocks = BinUtils.makeblocks(paddedplaintext,self.blocksize)
              ciphertext = self.iv
              for i in range(len(blocks)):
                  self.iv = b16encode(self.cipher.encrypt(b16decode(BinUtils.xorhexstrings(blocks[i],self.iv)))).decode('utf-8')
                  ciphertext += self.iv
              return ciphertext

     def decrypt(self, ciphertext :str):
         if self.mode == 'ECB':
             plaintext = self.cipher.decrypt(b16decode(ciphertext))
             return self.padding.unpad(plaintext)
         if self.mode == 'CBC':
             blocks = BinUtils.makeblocks(ciphertext,self.blocksize)
             plaintext = b''
             for i in range(len(blocks)-1,0,-1):
                 temp = b16decode(BinUtils.xorhexstrings(blocks[i-1],b16encode(self.cipher.decrypt(b16decode(blocks[i]))).decode('utf-8')))
                 if i == len(blocks)-1:
                     temp = self.padding.unpad(temp)
                 plaintext = temp + plaintext
             return plaintext


def isECB(ciphertext: str):
     blocks = BinUtils.makeblocks(ciphertext,AES.blocksize)
     return len(set(blocks)) < len(blocks)


class ByteAtATimeDecryptionECB:

    def __init__(self, oracle):
        # Trying to order bytes to minimize iterations
        initialBytes = ('etaoinshrdlcumwfgypbvkjxqz' + 'etaoinshrdlcumwfgypbvkjxqz'.upper() + string.digits + string.whitespace + string.punctuation).encode('utf-8')
        self.testbytes = initialBytes + b''.join([i.to_bytes(1,'little') for i in range(256) if i not in set(initialBytes)])
        self.oracle = oracle
        self.blocksize = 0
        self.textlength = 0

    def detect_blocklength(self):
        teststr = b''
        currentlength = len(self.oracle(teststr))
        self.textlength = currentlength//2
        while True:
            teststr += b'A'
            ciphertext = self.oracle(teststr)
            if currentlength < len(ciphertext):
                currentlength = len(ciphertext)
                break
        while True:
            teststr += b'A'
            self.blocksize += 1
            if currentlength < len(self.oracle(teststr)):
                return self.blocksize


    def detect_ECB(self):
        return isECB(self.oracle(b'A'*(3*self.blocksize)))

    def crack(self):
        test = b'A'*(self.blocksize-1)
        self.plaintext =  b''
        bufferblock = b'A'*(self.blocksize-1)
        t = trange(self.textlength)
        for i in t:
            for j in range(256):
                texttoprint = ''
                for k in range(len(self.plaintext)):
                    try:
                        texttoprint += self.plaintext[k:k+1].decode('utf-8')
                    except:
                        texttoprint += base64.b16encode(self.plaintext[k:k+1]).decode('utf-8')
                try:
                    texttoprint += self.testbytes[j:j+1].decode('utf-8')
                except:
                    texttoprint += base64.b16encode(self.testbytes[j:j+1]).decode('utf-8')

                texttoprint=texttoprint.replace('\n','\\n')
                t.set_description(f'plaintext = {texttoprint}')
                ciphertext = self.oracle(test+self.testbytes[j:j+1]+bufferblock)
                ciphertextblcoks = BinUtils.makeblocks(ciphertext,self.blocksize)
                if ciphertextblcoks[0] in ciphertextblcoks[1:]:
                    self.plaintext += self.testbytes[j:j+1]
                    break
            test = test[1:]+self.plaintext[len(self.plaintext)-1:len(self.plaintext)]
            if len(bufferblock) == 0:
                bufferblock = b'A'*(self.blocksize)
            bufferblock = bufferblock[1:]
        pkcs7 = PKCS7(self.blocksize)
        self.plaintext = pkcs7.unpad(self.plaintext)
        return self.plaintext.decode('utf-8')

    def run(self):
        self.detect_blocklength()
        self.detect_ECB()
        return self.crack()


def ECBemailcutandpaste(prefixlength :int, suffixlength :int, email :bytes,newtext :bytes, oracle :function, pad :function,blocksize=16):
    username, suffix = email.split(b'@')[0]
    prepad = (blocksize - ((prefixlength + len(username)+1)%blocksize))*b'A'
    newusername = username + b'+' + prepad
    block = (prefixlength + len(newusername))//blocksize
    newemail = newusername + pad(newusername) + suffixlength*b'A' + suffix
    print(newemail)