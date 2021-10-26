from utils.aesutils import *
from utils.aes import AES
from utils.binutils import FileHelper
from vulnexamples.aesvulns import SimpleInputECB, ExampleECBCBCOracle, ECBOrCBC, CBCBitFlip


class TestAES:
    def test_encrypt(self):
        assert True

    def test_decrypt(self):
        with open('../challenge_files/challenge7_decrypted.txt', 'rb') as f:
            plaintext = f.read()
        ciphertext = FileHelper.readb64filetohex('../challenge_files/challenge7.txt')
        cipher = AES(b'YELLOW SUBMARINE', 'ECB')
        assert cipher.decrypt(ciphertext) == plaintext

    def test_cbcdecrypt(self):
        with open('../challenge_files/challenge10_decrypted.txt', 'rb') as f:
            plaintext = f.read()
        ciphertext = FileHelper.readb64filetohex('../challenge_files/challenge10.txt')
        cipher = AES(b'YELLOW SUBMARINE', 'CBC')
        assert cipher.decrypt('00' * 16 + ciphertext) == plaintext


class Test_ECBOrCBC:
    def test_test(self):
        oracle = ExampleECBCBCOracle()
        isECBORCBC = ECBOrCBC(oracle.oracle)
        assert isECBORCBC.test() == oracle.isECB


class TestByteAtATimeDecryptECB:

    #    def __init__(self):
    #        ecboracle = SimpleInputECB(FileHelper.readb64filetobytes('../challenge_files/challenge12.txt'))
    #        self.baatecb = ByteAtATimeDecryptionECB(ecboracle.oracle)
    def test_detect_blocklength(self):
        ecboracle = SimpleInputECB(FileHelper.readb64filetobytes('../challenge_files/challenge12.txt'))
        baatecb = ByteAtATimeDecryptionECB(ecboracle.oracle)
        assert baatecb.detect_blocklength() == 16

    def test_detect_ecb(self):
        ecboracle = SimpleInputECB(FileHelper.readb64filetobytes('../challenge_files/challenge12.txt'))
        baatecb = ByteAtATimeDecryptionECB(ecboracle.oracle)
        baatecb.detect_blocklength()
        assert baatecb.detect_ECB()

    def test_crack(self):
        assert True


class TestCBCbitflipblocks:
    def test_cbcbitflipblocks(self):
        cbcbitflip = CBCBitFlip()
        ciphertext = cbcbitflip.create_ciphertext('A'*16)
        newctext = CBCbitflipblocks(ciphertext,3,b'A'*16,b'A;admin=true;A=A')
        assert cbcbitflip.parse_ciphertext(newctext)
