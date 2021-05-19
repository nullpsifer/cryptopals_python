import unittest
from utils import binutils


class TestBinUtils:

    # This tests challenge 1
    def test_hex2base64(self):
        hexstring = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
        base64string = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
        assert binutils.BinUtils.hex2base64(hexstring) == base64string

    def test_base642hex(self):
        hexstring = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
        base64string = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
        assert binutils.BinUtils.base642hex(base64string) == hexstring.upper()

    # This tests challenge 2
    def test_xorhexstrings(self):
        hexstring1 = '1c0111001f010100061a024b53535009181c'
        hexstring2 = '686974207468652062756c6c277320657965'
        hexstring3 = '746865206b696420646f6e277420706c6179'
        assert binutils.BinUtils.xorhexstrings(hexstring1, hexstring2) == hexstring3.upper()

    def test_makerepeatedkey(self):
        key = '1c2e'
        repeatedkey = '1c2e1c2e1c'
        assert binutils.BinUtils().makerepeatedkey(key, 10) == repeatedkey

    def test_hammingdistance(self):
        assert binutils.BinUtils.hammingdistance('this is a test','wokka wokka!!!') == 37
