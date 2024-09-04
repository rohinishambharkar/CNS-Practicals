import numpy as np
class Solution:
    def Playfair_Matrix(self,encrp_key):
        encrp_key="".join(dict.fromkeys(encrp_key))
        alp="ABCDEFGHIKLMNOPQRSTUVWXYZ"
        key=encrp_key+"".join([x for x in alp if x not in encrp_key])
        l=list(key)
        matrix=np.array(l).reshape(5,5)
        return matrix   

    def formatted_text(self,plaintext):
        extra=[]
        plaintext="".join([ch.upper() for ch in plaintext if ch.isalpha()])
        plaintext=plaintext.replace("J","I")
        text=[]
        i=0
        while i<len(plaintext):
            text.append(plaintext[i])
            if i+1<len(plaintext) and plaintext[i+1]==plaintext[i]:
                text.append("X")
                extra.append(len(text)-1)
            i+=1
        if len(text)%2==1:
            text.append("X") 
            extra.append(len(text)-1)       

        return "".join(text),extra
    
    def findPosition(self,letter,matrix):
        p=np.argwhere(matrix==letter)
        return p[0][0],p[0][1]
        
    def Encrypt_Pairs(self,pairs,matrix):
        r1,c1=Solution().findPosition(pairs[0],matrix)
        r2,c2=Solution().findPosition(pairs[1],matrix)
        if r1==r2:
            return matrix[r1][(c1+1)%5]+matrix[r2][(c2+1)%5]
        elif c1==c2:
            return matrix[(r1+1)%5][c1]+matrix[(r2+1)%5][c2]
        else:
            return matrix[r1][c2]+matrix[r2][c1]
        
    def Decrypt_Pairs(self,pairs,matrix):
        r1,c1=Solution().findPosition(pairs[0],matrix)
        r2,c2=Solution().findPosition(pairs[1],matrix)
        if r1==r2:
            return matrix[r1][(c1-1)%5]+matrix[r2][(c2-1)%5]
        elif c1==c2:
            return matrix[(r1-1)%5][c1]+matrix[(r2-1)%5][c2]
        else:
            return matrix[r1][c2]+matrix[r2][c1]

    def Encrypt(self,plaintext,encrp_key):
        matrix=Solution().Playfair_Matrix(encrp_key)
        print("Matrix generated: \n",matrix)
        formatted_plaintext,extra=Solution().formatted_text(plaintext)
        ciphertext=""
        for i in range(0,len(formatted_plaintext),2):
            ciphertext+=Solution().Encrypt_Pairs(formatted_plaintext[i:i+2],matrix)
        return ciphertext,extra   

    def Decrypt(self,ciphertext,decrypt_key,extra):
        matrix=Solution().Playfair_Matrix(decrypt_key)
        plaintext=""
        for i in range(0, len(ciphertext), 2):
            plaintext+=Solution().Decrypt_Pairs(ciphertext[i:i + 2],matrix)
        text=""
        for i in range(len(plaintext)):
            if i  not in extra:
                text+=plaintext[i]
        return text

            
plaintext="My Name is Jinx"
print("Plaintext: "+plaintext)
key="MONARCHY"
ciphertext,extra=Solution().Encrypt(plaintext,key)
print("\nEncrypted message: "+ciphertext)

a=Solution().Decrypt(ciphertext,key,extra)
print("Decrypted message: "+a)