import base64

class BinUtils:

    @staticmethod
    def hex2base64(hexstring):
        return base64.b64encode(base64.b16decode(hexstring.upper())).decode('utf-8')