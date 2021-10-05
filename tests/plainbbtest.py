from time import sleep
from gmpy2 import next_prime,  powmod, mpz
import os
from utils.pkcs15 import PKCS15, PKCS15Exception

def ceil(x,y):
    result = int(mpz(x)//mpz(y) + (mpz(x)%mpz(y)!=mpz(0)))
    assert 0<= (result*y)-x <=y-(x%y)
    return result

def floor(x,y):
    result = x//y
    assert 0<= x-result*y <=x%y
    return result

def generate_rsa_params(bytesize :int)->(int,int,int):
    while True:
        p = int(next_prime(int.from_bytes(os.urandom(bytesize),'big')))
        if p.bit_length() == bytesize*8:
            break
    while True:
        q = int(next_prime(int.from_bytes(os.urandom(bytesize),'big')))
        if q.bit_length() == bytesize*8:
            break
    n = p*q
    if n.bit_length() != 2*bytesize*8:
        print('Problem with n')
        return generate_rsa_params(bytesize)
    return p,q,p*q

class PlainBBTest:

    def __init__(self,bytelength :int,n :int,m :bytes):
        self.bytelength = bytelength
        self.n = n
        self.m = m
        self.pkcspad = PKCS15(self.bytelength)
        self.B = 1<<(8*(self.bytelength-2))
        self.B2 = 2* self.B
        self.B3 = 3* self.B
        self.solution = 0

    def finds0(self) -> (int,int):
        paddedmessage = self.pkcspad.pad(self.m)
        while True:
            s = int.from_bytes(os.urandom(self.bytelength),'big')
            mprime = (paddedmessage*s)%self.n
            try:
                self.pkcspad.unpad(mprime)
            except PKCS15Exception:
                continue
            return s, mprime

    def step1(self):
        self.s0,self.mprime = self.finds0()
        self.M = set([(self.B2,self.B3-1)])
        self.i = 1

    def step2(self):
        print(f'In step 2, self.i={self.i} len(self.M)={len(self.M)}')
        if self.i == 1:
            self.si= self.step2a()
            return True

        elif len(self.M)>1:
            temps = self.step2b()
            if temps <= self.si:
                print('***********SOMETHING BAD HAPPENED!!!***********')
            else:
                self.si = temps
            return True
        else:
            temps = self.step2c()
            if temps <= self.si:
                print('***********SOMETHING BAD HAPPENED!!!***********')
            else:
                self.si = temps
            return temps > 0

    def step2a(self):
        print('In step 2a')
        s1 = ceil(self.n,self.B3)
        while True:
            mprime = (s1*self.mprime)%self.n
            try:
                unpadded = self.pkcspad.unpad(mprime)
            except PKCS15Exception:
                s1 += 1
                continue
            return s1

    def step2b(self):
        print(f'In step 2b {len(self.M)}')
        si = self.si + 1
        while True:
            mprime = (si*self.mprime)%self.n
            try:
                unpadded = self.pkcspad.unpad(mprime)
            except PKCS15Exception:
                si +=1
                continue
            return si

    def step2c(self):
        print('In step2c')
        interval = self.M.pop()
        self.M.add(interval)
        a,b = interval
        r = ceil(2 * (b * self.si - self.B2), self.n)
        '''
        if not ((r-2*((b*self.si-self.B2)/self.n))<=1):
            print('****We did not get the smallest r*************')
            print(f'r={r}\n{2*((b*self.si-self.B2)/self.n)}\n{(r-2*((b*self.si-self.B2)/self.n))}')
            return 0
            r -= 1
            sleep(5)
        '''
        while True:
            startings = ceil(self.B2+r*self.n,b)
            endings = floor((self.B3+r*self.n),a)+1
            '''
            if not((startings - ((self.B2+r*self.n)/b))<=1):
                print('*********************We did not get the smallest s***********')
                print(f'startings = {startings}\n {((self.B2+r*self.n)/b)}\ndifference={(startings - ((self.B2+r*self.n)/b))}')
                return 0
                startings -=1
                sleep(5)
            '''
            for si in range(startings,endings):
                mprime = (si * self.mprime) % self.n
                try:
                    unpadded = self.pkcspad.unpad(mprime)
                except PKCS15Exception:
                    continue
                return si
            r += 1

    def step3(self):
        newM = set([])
        print('In step 3')
        for interval in self.M:
            print(interval)
            a,b=interval
            rlower = ceil(a * self.si - self.B3 + 1, self.n)
            '''
            if not ((rlower - ((a*self.si-self.B3+1)/self.n)) < 1):
                print(f'rlower too big\nrlower={rlower}\n{((a*self.si-self.B3+1)/self.n)}\ndifference= {(rlower - ((a*self.si-self.B3+1)/self.n))}')
                return False
                rlower -= 1
                sleep(3)
            '''
            rupper = ((b * self.si - self.B2)// self.n) + 1
            print(f'rlower={rlower} rupper={rupper} rupper-rlower={rupper-rlower}')
            for r in range(rlower,rupper):
                tempa = ceil(self.B2 + r * self.n, self.si)
                '''
                if (tempa - ((self.B2+r*self.n)/mpz(self.si))) >=1:
                    print('*****tempa is too big!*****')
                    print(f'tempa={tempa}\n{((self.B2+r*self.n)/mpz(self.si))}\ndifference = {tempa - ((self.B2+r*self.n)/mpz(self.si))}')
                    return False
                '''
                tempb = floor((self.B3 - 1 + r * self.n), self.si)
                '''
                if (tempb-(mpz(self.B3-1+r*self.n)/mpz(self.si))) >=1:
                    print('*****tempb is too small!*****')
                    print(f'tempb={tempb}\n{((self.B3-1+r*self.n)/mpz(self.si))}\ndifference ={tempb-(self.B3-1+r*self.n)/mpz(self.si)}')
                    return False
                '''
                newa = max(a,tempa)
                newb = min(b,tempb)
                if newa <= newb:
                    newM |= set([(newa,newb)])
        self.oldM = self.M
        if len(newM)>0:
            self.M = newM
        else:
            print('newM was empty')
        return True

    def step4(self):
        Mlist = list(self.M)
        if len(Mlist) == 1 and Mlist[0][1]==Mlist[0][0]:
            self.solution = int(list(self.M)[0][0]*powmod(self.s0,-1,self.n))%self.n
        else:
            print('Need to go back to step 2 again')
            self.i = self.i +1

    def currentsearchspacesize(self):
        return sum((x[1]-x[0] for x in self.M))
    def oneiteration(self):
        if not self.step2():
            return False
        if self.step3():
            self.step4()
            return True
        else:
            return False

    def run(self):
        self.step1()
        self.currentspacesize = self.currentsearchspacesize()
        while self.solution == 0:
            if not self.oneiteration():
                return False
            newsearchspace = self.currentsearchspacesize()
            if newsearchspace < self.currentspacesize:
                self.currentspacesize = newsearchspace
            else:
                print('search space did not decrease')
        return self.pkcspad.unpad(self.solution)