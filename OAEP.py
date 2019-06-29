import hashlib
import binascii
from random import SystemRandom
import Rsa

nBits = 1024
k0BitsInt = 256
k0BitsFill = '0256b'
errors = 'surrogatepass'
encoding = 'utf-8'




def CharsToBinary(msg, errors=errors):
    bits = bin(int.from_bytes(msg.encode(encoding, errors), 'big'))[2:]
    return bits.zfill(8 * ((len(bits) + 7) // 8))


def BinaryToChars(bits, errors):
    n = int(bits, 2)
    return n.to_bytes((n.bit_length() + 7) // 8, 'big').decode(encoding, errors) or '\0'


def pad(binMsg):
    oracle1 = hashlib.sha512()
    oracle2 = hashlib.sha512()
    randBitStr = format(SystemRandom().getrandbits(k0BitsInt), k0BitsFill)
    if len(binMsg) <= (nBits - k0BitsInt):
        k1Bits = nBits - k0BitsInt - len(binMsg)
        zeroPaddedMsg = binMsg + ('0' * k1Bits)
    else:
        zeroPaddedMsg = binMsg
    oracle1.update(randBitStr.encode(encoding))
    x = format(int(zeroPaddedMsg, 2) ^ int(oracle1.hexdigest(), 16), '0768b')
    oracle2.update(x.encode(encoding))
    y = format(int(oracle2.hexdigest(), 16) ^ int(randBitStr, 2), k0BitsFill)

    return x + y,len(binMsg)


def unpad(msg,bits):
    oracle1 = hashlib.sha512()
    oracle2 = hashlib.sha512()

    x = msg[0:768]
    y = msg[768:]

    oracle2.update(x.encode(encoding))
    r = format(int(y, 2) ^ int(oracle2.hexdigest(), 16), k0BitsFill)

    oracle1.update(r.encode(encoding))
    msgWith0s = format(int(x, 2) ^ int(oracle1.hexdigest(), 16), '0768b')
    msgWith0s = msgWith0s[0:bits] #remove the padding 0
    print("PADDED msg: ",msgWith0s)
    return BinaryToChars(msgWith0s, errors)


'''================================TESTING======================================'''

if __name__ == '__main__':

    size = eval(input("\nkey size: "))
    l1 = size // 2
    l2 = size - l1
    flag = 0
    while True:
        p = Rsa.get_prime(l1)
        q = Rsa.get_prime(l2)
        n = p * q
        x = p * q
        k = 0
        while x != 0:
            x = x >> 1
            k = k + 1
        if k > size and flag == 0:
            l1 = l1 - 1
            flag = 1
        if k > size and flag == 1:
            l2 = l2 - 1
            flag = 0
        if k == size:
            break

    e = 65537
    eular = (p - 1) * (q - 1)
    if Rsa.get_gcd(e, eular) == 1:
        x, y = Rsa.get_(e, eular)
        d = x % eular
    print("\npublic key: ", e, ', ', n)
    print("\nprivate key: ", d, ", ", n)
    instr = input("\nmessage= ")
    instr = bytes(instr, encoding='utf-8')
    plaintxt = int(binascii.b2a_hex(instr), 16)
    cipher = Rsa.fastExpMod(plaintxt, e, n)
    print("\nencripted= ", cipher)
    binmsg = CharsToBinary(str(cipher),errors)


    output,Bits = pad(binmsg)
    result = unpad(output,Bits)

    print("\nUNPADDED MSG:\n", result)
    cipher=int(result)
    interpret = Rsa.fastExpMod(cipher, d, n)
    int_string = binascii.a2b_hex(hex(interpret)[2:])

    print("\ndecripted= ", str(int_string, encoding='utf-8'))

    #print(len(result))