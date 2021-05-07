import  unittest
from utils import binutils


class TestBinUtils(unittest.TestCase):
    # This tests challenge 1
    def test_hex2base64(self):
        hexstring = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
        base64string = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
        assert binutils.BinUtils.hex2base64(hexstring) == base64string
