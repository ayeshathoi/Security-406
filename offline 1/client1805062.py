import socket            
from diffie1805062 import *
from aes1805062 import *

shared =""

DH = Diffie_Hellman()
def intToString(key):
    strKey = ''
    while key > 0:
        strKey += chr(key & 255)
        key >>= 8
    return strKey  

def publickey(key,g,prime):
    return DH.getpublicKey(key,g,prime)

    ###############################################################################

def shared(public, key, prime):
    return DH.getSharedKey(public,key,prime)



s = socket.socket()        
port = 12345               
s.connect(('127.0.0.1', port))

while True:
    msg = s.recv(1024).decode().split(" ")

    DH.setRange(128,10,2,100)
    half = int(128/2)
    BobRange   = 1 << (half+ 1)

    BobPrivateKey   =  DH.getprivateKey(BobRange,msg[0])
    publickey  = publickey(BobPrivateKey,msg[1],msg[0])

    s.send(str(publickey).encode())
    shared = shared(msg[2],BobPrivateKey,msg[0])
    print(shared)

    break



ciphertext = s.recv(1024).decode()

aes = AES()
aes.setKeyLength(128)
aes.setKey(intToString(shared))
keys = aes.GenerateKeyCalc()

string = ""
if len(ciphertext) >= 16 : 
    for i in range(0, len(ciphertext), 16):
        chunk = ciphertext[i:i+16]
        ciphertexthex = aes.convertCipherText(chunk)
        aes.decryption(ciphertexthex,keys)
        string += aes.ciphertext
        print("\nDeciphered Text : ")
        print("In Hex   : " + aes.ciphertexthex)
        print("In ASCII : " + aes.ciphertext)

print("Deciphered Text : " + string)
s.close()

