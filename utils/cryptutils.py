import base64
import binascii
import utils.binutils
import string


class XORCrypt():
    hexdigits = set(string.hexdigits)

    def __init__(self, key):
        tempkey = key
        if set(tempkey.upper()) < self.hexdigits:
            self.key = key
        else:
            self.key = base64.b16encode(key.encode('utf-8')).decode('utf-8')

    def crypt(self, text):
        localtext = text
        if not (set(localtext.upper()) < self.hexdigits):
            localtext = base64.b16encode(localtext.encode('utf-8')).decode('utf-8')
        try:
            return utils.binutils.BinUtils.xorhexstrings(utils.binutils.BinUtils.makerepeatedkey(self.key, len(localtext)),
                                                         localtext)
        except binascii.Error as e:
            if str(e) == 'Non-base16 digit found':
                hextext = base64.b16encode(text)
                return utils.binutils.BinUtils.xorhexstrings(
                    utils.binutils.BinUtils.makerepeatedkey(self.key, len(hextext)), hextext)


class ClassicalCryptAnalysis(object):
    letterorder = 'etaoinshrdlcumwfgypbvkjxqz'
    englishcharacters = string.ascii_lowercase + string.whitespace + '.,\'"-_'
    with open('/usr/share/dict/american-english') as f:
        dictwords = {line.strip().upper() for line in f}

    def __init__(self, text):
        self.text = text
        self.frequencyscore = 0
        self.aretherewords = False
        self.Englishwordcount = 0
        self.words = []

    def isEnglish(self):
        return set(self.text.lower()) < set(self.englishcharacters)

    def wordcountcheck(self):
        self.words = self.text.split()
        if 3 * len(self.words) < len(self.text) < 6 * len(self.words):
            self.aretherewords = True
        return self.aretherewords

    def checkwords(self):
        self.Englishwordcount = 0
        for word in self.words:
            if word.upper() in self.dictwords:
                self.Englishwordcount += 1
        return self.Englishwordcount

    def lettercount(self):
        lowertext = self.text.lower()
        self.lettercounts = []
        for letter in string.ascii_lowercase:
            self.lettercounts.append((lowertext.count(letter), letter))
        self.lettercounts.sort(key=lambda x: (x[0], 26 - self.letterorder.find(x[1])), reverse=True)

    def frequencyScore(self):
        self.frequencyscore = 0
        for i, lettercount in enumerate(self.lettercounts):
            if lettercount[1] == self.letterorder[i]:
                self.frequencyscore += 1


class SBXCryptAnalysis:
    def __init__(self, ctext):
        self.ctext = ctext
        self.possibleSolutions = []

    def scorekey(self, key):
        crypt = XORCrypt(key)
        potentialptext = crypt.crypt(self.ctext)
        candidate_ptext = base64.b16decode(potentialptext)
        try:
            candidate_ptext = candidate_ptext.decode('utf-8')
        except:
            return
        cryptanalysis = ClassicalCryptAnalysis(candidate_ptext)
        if cryptanalysis.isEnglish():
            cryptanalysis.lettercount()
            cryptanalysis.frequencyScore()
            self.possibleSolutions.append((cryptanalysis, key))

    def runkeys(self):
        for i in range(1, 256):
            self.scorekey(f'{i:02X}')
        self.possibleSolutions.sort(key=lambda x: x[0].frequencyscore, reverse=True)

    def checkIfFullText(self):
        solutionsToRemove = []
        for i, solution in enumerate(self.possibleSolutions):
            if not (solution[0].wordcountcheck() and len(solution[0].words)//2 < solution[0].checkwords() <= len(solution[0].words)):
                solutionsToRemove.append(i)
        solutionsToRemove.reverse()
        for i in solutionsToRemove:
            del self.possibleSolutions[i]

def findSBXinFile(filename):
    possibleSolutions = []
    with open(filename) as f:
        for ctext in f.readlines():
            sbx = SBXCryptAnalysis(ctext.strip())
            sbx.runkeys()
            sbx.checkIfFullText()
            if len(sbx.possibleSolutions)>0:
                possibleSolutions.append(sbx)
    return possibleSolutions