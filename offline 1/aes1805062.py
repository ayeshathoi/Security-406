from AESutils1805062 import *
############################################
from math import *
import time
import copy

############################################
class AES :

    blockSize = 128
           
    def setPlainText(self, text):
        self.asciiplainText = text
        self.plainText = self.check_keySize(text.encode().hex())
        self.matrixFormation(self.plainText,"plainText")

    def blockResize(self,key):
        blocks = []
        desired_size = 128
        size = len(key) * 4
        hex = 32

 
        if size < desired_size :
            blocks.append("0"*((desired_size - size)//4) + key)

        
        elif size >= desired_size :
            block_total = size/desired_size
            more=0
            if block_total.is_integer():
                block_total = int(block_total)
            else :
                more = block_total - floor(block_total)
                block_total = floor(block_total)
            
            lastBits=0
            for i in range(block_total):
                blocks.append(key[hex*i:hex*i+hex])
                lastBits = hex*i+hex
            if more!=0:
                blocks.append(key[lastBits:])
        return blocks
    
    def setKey(self,key):
        self.asciikeyText = key
        self.key = key.encode().hex()
        self.key = self.check_keySize(self.key)

    def setKeyLength(self,length):

        if(length == 128) :
            self.rounds = 10
        elif (length == 192) : 
            self.rounds = 12
        elif (length == 256) :
            self.roundConstant =4

        self.key_length = length

    def check_keySize(self,key):
        size = len(key) * 4
        if size < self.blockSize :
            moreCharNeeded = (self.blockSize - size)/4
            key = "0" * floor(moreCharNeeded) + key
        
        elif size > self.blockSize : 
            moreCharNeededForLast = (size - self.blockSize)/4
            key = key[0 : -ceil(moreCharNeededForLast)]

        return key
    

    def matrixFormation(self,hexTex, type) :
        matrix = [[],[],[],[]]
        length     = 0
        charLength = 2
        rowNum     = 0
        block      = 8

        while length < 32 :
            bitvec = BitVector(hexstring = hexTex[length : length + charLength])
            matrix[rowNum].append(bitvec)
            length += charLength

            if (length % block == 0 ) :
                rowNum += 1

        if type == "plainText" :
                self.matrix = matrix
                return matrix

        else :
                return matrix


        
    def transPoseMatrix(self,matrix):
        return list(map(list, zip(*matrix)))
         
    def LeftShift(self, wordMatrix, amount) :
        for i in range(amount):
            last = wordMatrix.pop(0)
            wordMatrix.append(last)
    
    def RightShift(self, wordMatrix, amount):
        for i in range(amount):
            last = wordMatrix.pop()
            wordMatrix.insert(0,last)

    
    def byteSubstitutionFromS_Box(self,wordMatrix,enc):
        for i in range(len(wordMatrix)):
            if enc == True:
                s_val = BitVector(intVal = Sbox[wordMatrix[i].intValue()],size = 8)
            else : 
                s_val = BitVector(intVal = InvSbox[wordMatrix[i].intValue()],size = 8)
            wordMatrix[i] = s_val



    def printout(self,row):
        for i in range(4) :
                print(row[i].get_bitvector_in_hex(),end = ' ')
        print()
       
    
    ###Round Constant Addition
    def gFunction(self,specificRow,index):
        #self.printout(specificRow)
        copyRow = copy.deepcopy(specificRow)
        self.LeftShift(copyRow,1)
        #self.printout(specificRow)
        self.byteSubstitutionFromS_Box(copyRow,True)
        #self.printout(specificRow)
        copyRow[0] = copyRow[0]^roundConstant[index]
        #self.printout(specificRow)
        return copyRow


    def GenerateKeyCalc(self):
     
        keys = []
        col = int(self.key_length / 32)
        keys.append(self.key)
        keyThisRound = self.key

        for round in range(self.rounds):
            keyMatrix = self.matrixFormation(keyThisRound,"key")
            #keyMatrix = self.keyMatrix(keyThisRound)
            temp = self.gFunction(keyMatrix[3],round)
        
            newKeyMatrix = [[0] * 4 for _ in range(col)]

            for i in range(4):
                newKeyMatrix[0][i] = keyMatrix[0][i] ^ temp[i]

            for i in range(4):
                newKeyMatrix[1][i] = newKeyMatrix[0][i] ^ keyMatrix[1][i]

            for i in range(4):
                newKeyMatrix[2][i] = newKeyMatrix[1][i] ^ keyMatrix[2][i]

            for i in range(4):
                newKeyMatrix[3][i] = newKeyMatrix[2][i] ^ keyMatrix[3][i]

            keyThisRound = ""
            for i in range(4):
                for j in range(col):
                    keyThisRound += newKeyMatrix[i][j].get_bitvector_in_hex()
            keys.append(keyThisRound)
                        
        self.roundkeys = keys
        #print(keys)
        return self.roundkeys

    
    def addRoundKey(self,roundkey,matrix):
        self.KeysRoundMatrix = self.matrixFormation(roundkey,"keys")
        keymat = self.transPoseMatrix(self.KeysRoundMatrix)
        for i in range (4):
            for j in range(4):
                self.matrix[i][j] = matrix[i][j] ^ keymat[i][j] 
        return self.matrix
                
    def newEmptyMatrix(self):
        new_state_Matrix = [[],[],[],[]]

        for i in range(4):
            for j in range(4):
                new_state_Matrix[i].append(BitVector(hexstring = "00"))
        return new_state_Matrix
    
    def mixOperations(self,newmat,matrix,time,row,col):

        for i in range(time):
            for j in range(col):
                for k in range(row):
                    newmat[i][j] = newmat[i][j]^matrix[i][k].gf_multiply_modular(self.matrix[k][j], AES_modulus, 8)

        return newmat

    def mix_column_encrypt(self,mat):
        mix_colmn_matrix = mat

        col = len(self.matrix[0])
        row = len(self.matrix)
        time = len(mix_colmn_matrix)
        
        new_state_Matrix = self.newEmptyMatrix()
        new_state_Matrix = self.mixOperations(new_state_Matrix,mix_colmn_matrix,time,row,col)
        return new_state_Matrix


    def hexAsciiFromMatrix(self,matrix):
        self.ciphertexthex=""
        self.ciphertext=""
        for i in range(4):
            for j in range(4):
                self.ciphertexthex += matrix[i][j].get_bitvector_in_hex()
                self.ciphertext += matrix[i][j].get_bitvector_in_ascii()




    def encryption(self):
        self.transposed_matrix = self.transPoseMatrix(self.matrix)
        self.matrix = self.addRoundKey(self.roundkeys[0],self.transposed_matrix)

        mat = Mixer

        #byte substitution
        for round in range(1, self.rounds + 1):

            for i in range(4):
                self.byteSubstitutionFromS_Box(self.matrix[i],True)
            

            #LEft Shift
            for i in range(4):
                self.LeftShift(self.matrix[i],i)

            #mix_column
            if round != (self.rounds):
                self.matrix = self.mix_column_encrypt(mat)

            self.matrix = self.addRoundKey(self.roundkeys[round],self.matrix)

        self.hexAsciiFromMatrix(self.matrix)

        #print(self.matrix)
        #print(self.matrix)


    def getCipherText(self):
        return self.ciphertext

    def getHexCipher(self):
        return self.ciphertexthex  


    def decryption(self,Cipher,Key):


        matrix = self.matrixFormation(Cipher,"plainText")
        #print(matrix)

        rounds = 10
        matrix = self.addRoundKey(Key[rounds],matrix)
        #print(Key)
        mat = InvMixer


        for round in range(1,rounds+1):

            for i in range(4):
                self.RightShift(matrix[i],i)

            for i in range(4):
                self.byteSubstitutionFromS_Box(matrix[i],False)

            matrix = self.addRoundKey(Key[rounds - round],matrix)

            if self.rounds - round !=0 :
               matrix = self.mix_column_encrypt(mat)

        matrix = self.transPoseMatrix(matrix)

        self.hexAsciiFromMatrix(matrix)
        #print(self.ciphertext)


    def convertCipherText(self,cipher):
        ciph = ""

        for c in cipher:
            ciph += str(BitVector(intVal = ord(c), size = 8 ))
        #hex_representation = [hex(ord(c)) for c in self.ciphertext]
        hex_representation = hex(int(ciph, 2))

        # Remove the '0x' prefix from the hexadecimal representation
        hex_representation = hex_representation[2:]
        return hex_representation


    def aesProcess(self):
        print("\nPlain Text : ")
        print("In ASCII : " + self.asciiplainText)
        print("In Hex   : " + self.plainText)

        print("\nKey : ")
        print("In ASCII : " + self.asciikeyText)
        print("In Hex   : " + self.key)

        start = time.time()
        roundKeys = self.GenerateKeyCalc()
        end   = time.time()
        self.keyTime = str(end - start)
        

        start = time.time()
        self.encryption()
        end   = time.time()
        self.encryptTime = str(end - start)
        
        print("\nCipher Text : ")
        print("In Hex   : " + self.ciphertexthex)
        print("In ASCII : " + self.ciphertext)


        start = time.time()

        cipher = self.convertCipherText(self.ciphertext)
        self.decryption(cipher,roundKeys)
        
        end   = time.time()
        self.decryptTime = str(end - start)

        
        print("\nDeciphered Text : ")
        print("In Hex   : " + self.ciphertexthex)
        print("In ASCII : " + self.ciphertext)

        print("\nExecution Time Details : ")
        print("Key Scheduling : " + self.keyTime + " seconds")
        print("Encryption Time : " + self.encryptTime + " seconds")
        print("Decryption Time : " + self.decryptTime + " seconds")


##################################################################
#independent aes implementation

choice = input("Console(press 1) or Input from File(press 2) : ")



aesIm = AES()
if choice == 1:
    plainText  = input("plain Text : ")
    key        = input("Key : ")
key_length = 128



f = open("plainText1805062.txt", "r")

plainText = f.read()
key        = input("Key : ")



blocks = aesIm.blockResize(plainText.encode().hex())

for block in blocks:
    ascii_string = ""
    for i in range(0, len(block), 2):
        hex_value = block[i:i+2]
        ascii_char = chr(int(hex_value, 16))
        ascii_string += ascii_char
    print(ascii_string)
    aes = AES()

    aes.setKeyLength(key_length)
    aes.setPlainText(ascii_string)
    aes.setKey(key)
    aes.aesProcess()
