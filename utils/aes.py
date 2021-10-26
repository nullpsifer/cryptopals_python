import os
from base64 import b16encode, b16decode

from Crypto.Cipher import AES as pycryptoAES

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
               self.iv = b16encode(iv).decode('utf-8')

     def encrypt(self,plaintext:bytes,iv=None):
         if self.mode == 'ECB':
              return b16encode(self.cipher.encrypt(self.padding.pad(plaintext))).decode('utf-8')
         if self.mode == 'CBC':
              ciphertext = ''
              if iv:
                  self.iv = b16encode(iv).decode('utf-8')
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