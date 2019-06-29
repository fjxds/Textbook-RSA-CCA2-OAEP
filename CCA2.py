from Crypto.Cipher import AES
import random
import numpy as np
from binascii import a2b_hex,b2a_hex
import Rsa as rsa

e=65537
class WUP:
    def __init__(self,req="",res="",k=""):
        self.request=req
        self.response=res
        self.key=k

class server:

    def __init__(self):
        self.p=rsa.get_prime(512)
        self.q=rsa.get_prime(512)
        self.n=self.p*self.q
        self.eular=(self.p-1)*(self.q-1)
        x, y = rsa.get_(e,self.eular)
        self.d=x%self.eular
        self.aes=random.randrange(1<<127,2**128)
        while self.aes%2==0:
            self.aes = random.randrange(1 << 127, 2 ** 128)
    def generate_his(self):
        w=WUP()
        request="You have succeeded!"
        length=16
        count=len(request)
        if (count%length!=0):
            add=length-(count%length)
        else:
            add=0
        request=request+('\0'*add)
        cryptor=AES.new(a2b_hex(hex(self.aes)[2:]),AES.MODE_ECB)
        w.request=b2a_hex(cryptor.encrypt(request))
        response="Success"
        count = len(response)
        if (count % length != 0):
            add = length - (count % length)
        else:
            add = 0
        response = response + ('\0' * add)
        w.response=b2a_hex(cryptor.encrypt(response))
        w.key=rsa.fastExpMod(self.aes,e,self.n)
        return w
    def decypt(self,txt):
        decryptor=AES.new(a2b_hex(hex(self.aes)[2:]),AES.MODE_ECB)
        plain_text=str(decryptor.decrypt(a2b_hex(txt)),'utf-8')
        return plain_text.rstrip('\0')
    def test(self,wup):
        aes=bin(rsa.fastExpMod(wup.key,self.d,self.n))[-128:]
        aes=int(aes,2)
        string=""
        for i in hex(aes)[2:]:
            string+=i
        add=32-len(string)
        string='0'*add+string
        #print(string)
        decryptor=AES.new(a2b_hex(string),AES.MODE_ECB)
        plain_text=decryptor.decrypt(a2b_hex(wup.request))
        #plain_text=plain_text.rstrip('\0')
        return plain_text


s=server()
his=s.generate_his()
print("req: ",str(his.request,encoding='utf-8'))
print("res: ",str(his.response,encoding='utf-8'))
print("key: ",his.key)
current_key=0
for i in range(128,0,-1):
    k_i=int(current_key>>1)+(1<<127)
    print("k"+str(i-1),": ",bin(k_i)[2:])
    request="test WUP request"
    length = 16
    count = len(request)
    if (count % length != 0):
        add = length - (count % length)
    else:
        add = 0
    request = request + ('\0' * add)
    encryptor=AES.new(a2b_hex(hex(k_i)[2:]),AES.MODE_ECB)
    encrypted=str(b2a_hex(encryptor.encrypt(request)),'utf-8')
    print("encrypted msg: ",encrypted)
    factor=rsa.fastExpMod(2,(i-1)*e,s.n)
    encrypted_key=rsa.fastExpMod(his.key*factor,1,s.n)
    re=s.test(WUP(encrypted,"",encrypted_key))
    print("response: ",re)
    if re==b"test WUP request":
        current_key=k_i
        print("current key:", current_key)
    else:
        k_i=int(current_key>>1)
        print("k"+str(i - 1), ": ", bin(k_i)[2:])
        string=""
        for j in hex(k_i)[2:]:
            string+=j
        ad=32-len(string)
        string='0'*ad+string
        encryptor = AES.new(a2b_hex(string), AES.MODE_ECB)
        encrypted = str(b2a_hex(encryptor.encrypt(request)),'utf-8')
        print("encrypted msg: ", encrypted)
        factor = rsa.fastExpMod(2, (i - 1) * e, s.n)
        encrypted_key = rsa.fastExpMod(his.key * factor, 1, s.n)
        re = s.test(WUP(encrypted, "", encrypted_key))
        current_key=k_i
        print("response: ", re)
        print("current key: ",current_key)
    print("\n")

decryptor=AES.new(a2b_hex(hex(current_key)[2:]),AES.MODE_ECB)
plain_text=str(decryptor.decrypt(a2b_hex(his.request)),'utf-8')
plain_text=plain_text.rstrip('\0')
print("History information: ",plain_text)

