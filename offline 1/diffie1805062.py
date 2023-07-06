from math import *
import random

class Diffie_Hellman :

    def mod_expo(self,base, exponent, modulo):
        result = 1
        base = base % modulo
        while exponent > 0 :
            if (exponent & 1):
                result = (result * base) % modulo
            exponent = exponent >> 1
            base = (base * base) % modulo
        
        return result
    
 
    def miillerTest(self,d, num):
    
        a = 2 + random.randint(1, num - 4)
        x = self.mod_expo(a, d, num)
    
        if (x == 1 or x == num - 1):
            return True

        while (d != num - 1):
            x = (x * x) % num
            d *= 2
    
            if (x == 1):
                return False
            if (x == num - 1):
                return True

        return False
    
    def isPrime(self,num, iteration):

        if (num <= 1 or num == 4):
            return False
        if (num <= 3):
            return True

        d = num - 1
        while (d % 2 == 0):
            d //= 2
    
        for i in range(iteration):
            if (self.miillerTest(d, num) == False):
                return False
    
        return True
    
    
    def safePrime(self):
        while True:
            p = self.randomNumberGeneration()
            q = 2 * p + 1
            if self.isPrime(q, self.iteration) and self.isPrime(p, self.iteration):
                self.largePrime = q
                self.smallPrime = p
                if self.findPrimitiveRoot():
                    return q

            
    def findPrimitiveRoot(self):
        phi = self.largePrime - 1
    
        factors = set()
        factors.add(2)
        factors.add(self.smallPrime)
 
        for r in range(self.min, self.max):
            flag = False
            for it in factors:
                if (self.mod_expo(r, phi // it, self.largePrime) == 1):
                    flag = True
                    break
            if (flag == False):
                self.base = r
                return self.base
    
        return -1
    
    def setRange(self,length,iteration,min,max):
        self.length = length
        self.half = int(length/2)
        self.halfl = 1 << self.half
        self.left = 1 << (length - 1)
        self.right = (1 << length) - 1
        self.iteration = iteration
        self.min = min
        self.max = max
    
    def randomNumberGeneration(self):
        return random.randrange(self.left,self.right)
    
    def randomPrime(self,left,right):
        for findPrime in range(left,right):
            if (self.isPrime(findPrime, self.iteration)):
                return findPrime
            
    # def diffie_hellman(self,start,prime,base):
    #     a = self.randomPrime(start,prime)
    #     A = self.mod_expo(base, a, prime)
    #     self.privatekeya = a 
    #     self.publicKeyA = A

    def getprivateKey(self,start,prime):
        return self.randomPrime(start,int(prime))
    
    def getpublicKey(self,a,base,prime):
        return self.mod_expo(int(base), a, int(prime))

    def getSharedKey(self,publicKey,privateKey,Prime):
        return self.mod_expo(int(publicKey),privateKey,int(Prime))