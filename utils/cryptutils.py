import base64
from dataclasses import dataclass
import binascii
from gmpy2 import mpq
from utils.binutils import BinUtils
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
            return BinUtils.xorhexstrings(BinUtils.makerepeatedkey(self.key, len(localtext)),
                                                         localtext)
        except binascii.Error as e:
            if str(e) == 'Non-base16 digit found':
                hextext = base64.b16encode(text)
                return BinUtils.xorhexstrings(
                    BinUtils.makerepeatedkey(self.key, len(hextext)), hextext)


class ClassicalCryptAnalysis(object):
    letterorder = 'etaoinshrdlcumwfgypbvkjxqz'
    englishcharacters = set(string.ascii_lowercase + string.whitespace + '?!.,\'"-_'+string.digits)
    #englishcharacters = set(string.printable)
    with open('/usr/share/dict/american-english') as f:
        dictwords = {line.strip().upper() for line in f}

    def __init__(self, text):
        self.text = text
        self.frequencyscore = 0
        self.aretherewords = False
        self.Englishwordcount = 0
        self.words = []

    def isEnglish(self):
        return set(self.text.lower()) < self.englishcharacters

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

@dataclass(frozen=True)
class HammingDistanceData:
    distance: int
    length: int
    numofblocks: int
    def __gt__(self, other):
        if other.__class__ is self.__class__:
            return mpq(self.distance,self.length*self.numofblocks) > mpq(other.distance,other.length*other.numofblocks)

class RepeatingKeyXorCA:

    def __init__(self,ctext):
        self.ctext = ctext
        self.distances = []
        self.keys = []
        self.possibleSolutions = []

    def createTransposedBlocks(self,keysize):
        transposeBlocks = keysize*['']
        transposeBlockIndex = 0
        for i in range(0,len(self.ctext),2):
            transposeBlocks[transposeBlockIndex] += self.ctext[i:i+2]
            transposeBlockIndex += 1
            transposeBlockIndex %= keysize
        return transposeBlocks

    @classmethod
    def generatePossibleKeys(cls,sbxcas):
        if len(sbxcas) == 1:
            return [possibleSolution[1] for possibleSolution in sbxcas[0].possibleSolutions]
        startofkeys = [possibleSolution[1] for possibleSolution in sbxcas[0].possibleSolutions]
        keyparts = []
        remainingParts = cls.generatePossibleKeys(sbxcas[1:])
        for i in range(len(startofkeys)):
            for j in range(len(remainingParts)):
                keyparts.append(startofkeys[i]+remainingParts[j])
        return keyparts

    def tryKeySize(self,keysize):
        transposedBlocks = self.createTransposedBlocks(keysize)
        sbxcas = [SBXCryptAnalysis(block) for block in transposedBlocks]
        for sbxca in sbxcas:
            sbxca.runkeys()
        return sbxcas

    def findKeySize(self):
        for i in range(2,41):
            blocks = BinUtils.makeblocks(self.ctext,i)
            distance = 0
            for j in range(len(blocks)):
                distance += BinUtils.hammingdistance(blocks[i],blocks[i+1])
            self.distances.append(HammingDistanceData(distance,i,len(blocks)))
        self.distances.sort()

    def checkkeysizes(self):
        for i in range(4):
            sbxcas = self.tryKeySize(self.distances[i].length)
            generateFullKey = True
            for sbxca in sbxcas:
                if len(sbxca.possibleSolutions) == 0:
                    generateFullKey = False
                    break
            if generateFullKey:
                self.keys += self.generatePossibleKeys(sbxcas)

    def checkkeys(self):
        for key in self.keys:
            xorcrypt = XORCrypt(key)
            ptext = base64.b16decode(xorcrypt.crypt(self.ctext)).decode('utf-8')
            cca = ClassicalCryptAnalysis(ptext)
            if cca.wordcountcheck():
                wordsindict = cca.checkwords()
                if len(cca.words)//2 < wordsindict <= len(cca.words):
                    self.possibleSolutions.append((ptext,key))

    def crack(self):
        self.findKeySize()
        self.checkkeysizes()
        self.checkkeys()
        return self.possibleSolutions


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
