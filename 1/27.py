from util import *

key = keygen()
iv = key

def verify_ascii(data):
    nums = str_to_nums(data)
    if not all([n >= 32 or n == 10 for n in nums]):
        raise Exception(data)

def encrypt(data):
    return cbc_encrypt(data, key, iv)

def decrypt(msg):
    plain = strip_padding(cbc_decrypt(msg, key, iv))
    verify_ascii(plain)
    return plain

# Method:
# In CBC mode, p2 is XOR'd with c1 before going into the block cipher. 
# If the iv is the same as the key, then the input to the block cipher is
# enc(p1 xor key) xor p2. If p2 is all 0s, then it is just enc(p1 xor key).
# Then the input to the block cipher for block 3 is enc(enc(p1 xor key)) xor p3.
# c1 = enc(p1 xor key)
# During decryption, p`3 = c2 xor dec(c3). If c2 is all 0s then it is just dec(c3).
# If c1 and c3 are the same, then we get p`1 = dec(c3) xor key, so p`1 xor p`3 == key.
if __name__ == '__main__':
    msg = '''You wake up late for school man you don't wanna go
    You ask you mom, "Please?" but she still says, "No!"
    You missed two classes and no homework
    But your teacher preaches class like you're some kind of jerk
    '''.strip()
    enc = encrypt(msg)
    enc2 = enc[:16] + chr(0) * 16 + enc[:16] + enc[16:]
    try:
        decrypted = decrypt(enc2)
        print decrypted
    except Exception, e:
        print 'Caught exception'
        p = str(e)
        p1 = p[:16]
        p3 = p[32:48]
        k = xor_byte_strings(p1, p3)

        print key == k
