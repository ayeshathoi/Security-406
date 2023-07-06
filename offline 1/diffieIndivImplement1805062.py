from diffie1805062 import *
from math import *
import time

def writeFile(filename,fileContent):
    f = open(filename+".txt", "w")
    f.write(fileContent)
    f.close()




k = input("length :" )
# mn = input("min :")
# mx = input("max :")
# f = input("iteration in miller : ")
# min = int(mn)
# max = int(mx)
min = 2
max = 100
iteration = 10
length = int(k)

half = int(length/2)
AliceRange = 1 << (half)
BobRange   = 1 << (half + 1)

DH = Diffie_Hellman()
DH.setRange(length,iteration,min,max)


start = time.time()
for i in range(5):
    prime = DH.safePrime()
end   = time.time()
primeCalcTime = str((end - start)/5)
        

start = time.time()
for i in range(5):
    g = DH.findPrimitiveRoot()
end   = time.time()
gCalcTime = str((end - start)/5)


start = time.time()
for i in range(5):
    AliceprivateKey =  DH.getprivateKey(AliceRange,prime)
end   = time.time()
aTime = str((end - start)/5)

start = time.time()
for i in range(5):
    AlicepublicKey  =  DH.getpublicKey(AliceprivateKey,g,prime)
end   = time.time()
Atime = str((end - start)/5)

##############################################################################

AliceKeys = str(prime) + " " + str(g) +" " + str(AlicepublicKey)
writeFile("Bob",AliceKeys)

file = open("Bob.txt", "r")
AliceSent_key = file.read().split(' ')


BobPrivateKey   =  DH.getprivateKey(BobRange,AliceSent_key[0])
#BobpublicKey   =   DH.getpublicKey(BobPrivateKey,g)
BobpublicKey   =   DH.getpublicKey(BobPrivateKey,AliceSent_key[1],AliceSent_key[0])

BobKeys = str(BobpublicKey)
writeFile("Alice",BobKeys)

file = open("Alice.txt", "r")
BobSent_key = file.read().split(' ')

###############################################################################

start = time.time()
for i in range(5):
    BobSharedKey = DH.getSharedKey(AliceSent_key[2],BobPrivateKey,AliceSent_key[0])
end   = time.time()
shareKeytime = str((end - start)/5)

###############################################################################
writeFile("Bob",str(BobSharedKey))
print("Calculated Bob's sharedKey")
###############################################################################



AliceSharedKey = DH.getSharedKey(BobSent_key[0],AliceprivateKey,prime)

###############################################################################
writeFile("Alice",str(AliceSharedKey))
print("Calculated Alice's sharedKey")
###############################################################################



if BobSharedKey == AliceSharedKey :
    print("matched")





# keys = str(AliceprivateKey) + " " + str(AlicepublicKey)  + " " + str(BobPrivateKey) + " " + str(BobpublicKey) + " " + str(BobSharedKey)

# writeFile("Keys",keys)


print("KeyLength : ")
print(length)

print("Computation time for p         : " + primeCalcTime + " seconds")
print("Computation time for g         : " + gCalcTime + " seconds")
print("Computation time for a or b    : " + aTime + " seconds")
print("Computation time for A  or B   : " + Atime + " seconds")
print("Computation time for sharedkey : " + shareKeytime + " seconds")

