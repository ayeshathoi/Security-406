from math import *
from BitVector import *
from diffie1805062 import *

class RSA :
	def setKeyLength(self,key_length):
		self.key_length = key_length

	def greatestCommonDivisor(self, num1, num2):
		return gcd(num1,num2)
	
	def coprime(self,num,num2):
		return self.greatestCommonDivisor(num,num2)==1

	def eGeneration(self):
		start = 2
		for i in range(start,self.phi):
			if self.coprime(i,self.phi):
				e=i
				break
		return e


	def generateKeys(self,prime1,prime2):
		self.modulus = prime1 * prime2
		self.phi = (prime1 - 1) * (prime2 - 1 )
		
		self.e = self.eGeneration()
		self.d = BitVector(intVal=self.e).multiplicative_inverse(BitVector(intVal=self.phi)).int_val()

		self.publicKey = ( self.modulus, self.e)
		self.privateKey = ( self.modulus, self.d)

	def printKeys(self):
		print("Public  Key : " + str(self.publicKey))
		print("Private Key : " + str(self.privateKey))

	



key_length = int(input("input key length :"))

rsa = RSA() 
iteration = 10

DH = Diffie_Hellman()
DH.setRange(key_length,iteration,2,100)

prime1 = DH.randomPrime(DH.halfl,DH.left)
prime2 = DH.randomPrime(DH.left,DH.right)
print("1st Prime : " + str(prime1))
print("2nd Prime : " + str(prime2))

rsa.generateKeys(prime1,prime2)

print("Generated keys")
rsa.printKeys()