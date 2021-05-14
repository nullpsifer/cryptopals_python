import base64

class BinUtils:

    @staticmethod
    def hex2base64(hexstring):
        return base64.b64encode(base64.b16decode(hexstring.upper())).decode('utf-8')

    @staticmethod
    def base642hex(b64string):
        return base64.b16encode(base64.b64decode(b64string)).decode('utf-8')

    @staticmethod
    def xorhexstrings(hexstring1,hexstring2):
        assert len(hexstring1) == len(hexstring2) and len(hexstring2) % 2 == 0
        return f'{int(hexstring1,16)^int(hexstring2,16):0{len(hexstring2)}X}'

    @staticmethod
    def makerepeatedkey(key,textlength):
        newkey = textlength//len(key) * key
        newkey += key[:textlength%len(key)]
        return newkey