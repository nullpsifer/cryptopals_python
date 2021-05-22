from base64 import b16decode, b16encode
from Crypto.Cipher import AES as pycryptoAES
from utils.pkcs7 import PKCS7

class AES:
     blocksize = 16
     padding = PKCS7(blocksize)
     def __init__(self,key :bytes,mode :str,iv=None):
          self.cipher = pycryptoAES.new(key,pycryptoAES.MODE_ECB)
          self.mode = mode
          if iv:
               self.iv = iv

     def encrypt(self,plaintext):
         if self.mode == 'ECB':
              return b16encode(self.cipher.encrypt(plaintext)).decode('utf-8')

     def decrypt(self, ciphertext :str):
          if self.mode == 'ECB':
               plaintext = self.cipher.decrypt(b16decode(ciphertext))
          return self.padding.unpad(plaintext)