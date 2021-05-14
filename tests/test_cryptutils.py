from utils.cryptutils import *
import os


class TestSBXCryptAnalysis:
    # Challenge 3
    def test_ifFullText(self):
        ctext = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
        sbxc = SBXCryptAnalysis(ctext)
        sbxc.runkeys()
        sbxc.checkIfFullText()
        possibleSolutions = sbxc.possibleSolutions
        solution = possibleSolutions[0]
        assert len(possibleSolutions) == 1 and solution[0].text == "Cooking MC's like a pound of bacon" and solution[
            1] == '58'


class TestClassicalCryptAnalysis:
    def test_is_english(self):
        assert False

    def test_wordcountcheck(self):
        assert False

    def test_lettercount(self):
        assert False

    def test_frequency_score(self):
        assert False


# Challenge 4
def test_findSBXinFile():
    possibleSolutions = findSBXinFile('../challenge_files/challenge4.txt')
    solution = possibleSolutions[0]
    solution1 = solution.possibleSolutions[0]
    assert len(possibleSolutions) == 1 and len(solution.possibleSolutions) == 1 and solution1[
        0].text == 'Now that the party is jumping\n' and solution1[1] == '35'


class TestXORCrypt:
    # Challenge 5
    def test_crypt(self):
        plaintext = '''Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal'''
        xorcrypt = XORCrypt('ICE')
        ciphertext = '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'
        print(f'plaintext length= {len(plaintext)}\nciphertext length = {len(ciphertext)}')
        assert xorcrypt.crypt(plaintext) == ciphertext.upper()
