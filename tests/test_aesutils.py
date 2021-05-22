from utils.aesutils import AES
from utils.binutils import FileHelper
class TestAES:
    def test_encrypt(self):
        assert False

    def test_decrypt(self):
        with open('../challenge_files/challenge7_decrypted.txt', 'rb') as f:
            plaintext = f.read()
        ciphertext = FileHelper .readb64filetohex('../challenge_files/challenge7.txt')
        cipher = AES(b'YELLOW SUBMARINE','ECB')
        assert cipher.decrypt(ciphertext) == plaintext
