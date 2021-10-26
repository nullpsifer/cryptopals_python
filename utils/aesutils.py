import base64
import string
from tqdm import trange, tqdm
from utils.aes import AES
from utils.binutils import BinUtils
from utils.pkcs7 import PKCS7


def isECB(ciphertext: str):
     blocks = BinUtils.makeblocks(ciphertext, AES.blocksize)
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


def ECBemailcutandpaste(prefixlength :int, suffixlength :int, email :bytes,newtext :bytes, oracle :callable, pad :callable,blocksize=16):
    username, suffix = email.split(b'@')
    prepad = (blocksize - ((prefixlength + len(username)+1)%blocksize))*b'A'
    newusername = username + b'+' + prepad
    block = (prefixlength + len(newusername))//blocksize
    newemail = newusername + pad(newtext) + (blocksize-((suffixlength+1+len(suffix))%blocksize))*b'A' + b'@'+suffix
    return newemail.decode('utf-8')

def CBCbitflipblocks(ciphertext :str, blocktoflip :int, originalbytes :bytes, newbytes :bytes, blocksize=16) -> bytes:
    blocks = BinUtils.makeblocks(ciphertext.encode('utf-8'),blocksize)
    blocks[blocktoflip-1] = base64.b16encode((int(blocks[blocktoflip-1],16)^int.from_bytes(originalbytes,'big')^int.from_bytes(newbytes,'big')).to_bytes(blocksize,'big'))
    return b''.join(blocks)

class PaddingOracleAttack:

    def __init__(self,ciphertext :str,oracle :callable,blocksize=16):
        self.blocksize = blocksize
        self.ctextblocks = BinUtils.makeblocks(ciphertext.encode('utf-8'), self.blocksize)
        self.oracle = oracle
        self.paddingsize = 1
        self.numberofctextblocks = len(self.ctextblocks)-1
        self.tqdm = tqdm(total=16*self.numberofctextblocks)
        self.currentblock = self.numberofctextblocks
        self.plaintext = bytearray(b'')
        self.pad = 1
        self.currentblockint = int(self.ctextblocks[self.currentblock-1],16)
        self.keepgoing = True
        self.beginning = True

    def makepad(self):
        self.pad = 0
        for i in range(self.paddingsize):
            self.pad |= self.paddingsize << (8*i)

    def increment_pad(self):
        self.paddingsize +=1
        if self.paddingsize > self.blocksize:
            self.paddingsize = 1
            self.currentblock -=1
            self.plaintext = self.guess + self.plaintext
            self.initialize_guess()
            self.currentblockint = int(self.ctextblocks[self.currentblock - 1], 16)
            if self.currentblock == 0:
                self.keepgoing = False
        self.makepad()

    def initialize_guess(self):
        self.guess = bytearray((b'\x00'*(self.blocksize-1))+(b'\x10' if self.beginning else b'\x20'))

    def print_currentguess(self):
        currentplaintext = b'0'*(2*self.blocksize*(self.currentblock-1))+base64.b16encode(self.guess) + base64.b16encode(self.plaintext)
        self.tqdm.set_description(f'Current guess: {currentplaintext.decode("utf-8")}')

    def update_guess(self):
        if self.beginning:
            self.guess[-self.paddingsize] = (self.guess[-self.paddingsize]-1)%256
        else:
            self.guess[-self.paddingsize] = (self.guess[-self.paddingsize]+1)%256

    def replaceblock(self):
        self.replacementblock = f'{int.from_bytes(self.guess,"big")^self.pad^self.currentblockint:0{2*self.blocksize}X}'.encode('utf-8')

    def makeciphertext(self):
        return b''.join(self.ctextblocks[:self.currentblock-1]+[self.replacementblock,self.ctextblocks[self.currentblock]])

    def step(self):
        self.replaceblock()
        ciphertext = self.makeciphertext()
        self.print_currentguess()
        if self.oracle(ciphertext):
            if self.beginning:
                self.paddingsize = self.guess[-1]
                self.guess =bytearray(b'\x00'*(self.blocksize-self.paddingsize)+self.guess[-1].to_bytes(1,'big')*self.paddingsize)
                self.beginning = False
                self.tqdm.update(n=self.paddingsize)
            else:
                self.tqdm.update(n=1)
            self.increment_pad()
        self.update_guess()

    def runattack(self):
        self.initialize_guess()
        while self.keepgoing:
            #self.print_currentguess()
            self.step()
        pad = PKCS7()
        return pad.unpad(self.plaintext).decode('utf-8')