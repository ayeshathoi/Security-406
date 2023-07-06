import socket			
from aes1805062 import *
from AESutils1805062 import *
from diffie1805062 import *

##################################################

def AliceKeyProcess(publickey):
    return DH.getSharedKey(publickey,AliceprivateKey,prime)


def intToString(key):
    strKey = ''
    while key > 0:
        strKey += chr(key & 255)
        key >>= 8
    return strKey  

#############################################################################
DH = Diffie_Hellman()
#k = input("Key Length :" )
# mn = input("min :")
# mx = input("max :")
# f = input("iteration in miller : ")
# min = int(mn)
# max = int(mx)
k = 128
min = 2
max = 100
iteration = 10
length = int(k)

half = int(length/2)
AliceRange = 1 << (half)

DH = Diffie_Hellman()
DH.setRange(length,iteration,min,max)

prime = DH.safePrime()
g = DH.findPrimitiveRoot()
AliceprivateKey =  DH.getprivateKey(AliceRange,prime)
AlicepublicKey  =  DH.getpublicKey(AliceprivateKey,g,prime)

##############################################################################


plainText = input("plainText :")

keyLength = 128


cipher =[]
cipherHex = []
def Proccessing(key):
    aesEnc = AES()
    blocks = aesEnc.blockResize(plainText.encode().hex())

    string = ""
    for block in blocks:
        ascii_string = ""
        for i in range(0, len(block), 2):
            hex_value = block[i:i+2]
            ascii_char = chr(int(hex_value, 16))
            ascii_string += ascii_char
        
        print(ascii_string)
    
        aes = AES()
        aes.setPlainText(ascii_string)
        aes.setKey(key)
        aes.setKeyLength(128)
        aes.GenerateKeyCalc()
        aes.encryption()
        cipher.append(aes.ciphertext)
        string += aes.ciphertext
    return string

s = socket.socket()		
print ("Socket successfully created")
port = 12345			
s.bind(('', port))		
print ("socket binded to %s" %(port))

s.listen(5)	
print ("socket is listening")		


while True:
    c, addr = s.accept()	
    c.send((str(prime) + " " + str(g) +" " + str(AlicepublicKey)).encode())
    bobPublicKey = c.recv(1024).decode()
    shared = AliceKeyProcess(bobPublicKey)
    print(shared)
    break

string = Proccessing(intToString(shared))
#### msg processing
c.send(string.encode())

c.close()
