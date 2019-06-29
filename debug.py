import base64
import binascii
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto import Random
import rsa

random_generator=Random.new().read
file="secret.txt"
c=""
with open(file,"rb") as f:
    cipher=f.read()
    instr=base64.b64decode(cipher)
    print(instr)
    #instr=str(binascii.b2a_hex(instr),'utf-8')
file="rsa_private_key.pem"
default_length=117
with open(file,"rb") as f:
    line=f.read()
    rsaKey=RSA.importKey(line)
    decryptor=PKCS1_v1_5.new(rsaKey)
    privkey = rsa.PrivateKey.load_pkcs1(line)
    #encrypted_byte=base64.b64decode(cipher.encode())
    '''length=len(encrypted_byte)
    if length < default_length:
        decrypt_byte = decryptor.decrypt(encrypted_byte, 'failure')
    else:
        offset = 0
        res = []
        while length - offset > 0:
            if length - offset > default_length:
                res.append(decryptor.decrypt(encrypted_byte[offset: offset + default_length], 'failure'))
            else:
                res.append(decryptor.decrypt(encrypted_byte[offset:], 'failure'))
            offset += default_length
        decrypt_byte = b''.join(res)
    decrypted = decrypt_byte.decode()'''
    print(decryptor.decrypt(instr,random_generator))
    rsa.decrypt(instr, privkey)