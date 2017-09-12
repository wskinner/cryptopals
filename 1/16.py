from util import *

iv = keygen()
key = keygen()
def wrap(data):
    def escape(st):
        return st.replace('=', '%3D').replace(';', '%3B')

    wrapped = "comment1=cooking%20MCs;userdata=" + escape(data) + ";comment2=%20like%20a%20pound%20of%20bacon"
    padded = pkcs7_pad(wrapped)
    return cbc_encrypt(padded, key, iv)

def check(enc):
    plain = cbc_decrypt(enc, key, iv)
    print plain
    return ';admin=true;' in plain 

# Cn = the nth ciphertext block
# AESn = the nth AES output block (pre xoring)
# Pn = the nth plaintext block
# Pn = Cn-1 xor AESn
# We know Pn and Cn. Given a desired Pn, choose Cn-1.
# Cn-1 xor Y = Pn
# Y = Pn xor Cn-1
# Choose Cn-1 = Y xor target
def inject():
    target = ';admin=true;aaaa'
    assert len(target) == 16
    pre = "comment1=cooking%20MCs;userdata="
    # This is the index of the block we're going to use
    block_i = len(pre) / 16
    
    # Chosen plaintext
    pn = 16 * 'a'
    cipher = wrap(pn)
    cn1 = cipher[(block_i - 1) * 16: block_i * 16]
    Y = xor_byte_strings(cn1, pn)
    chosen_cn1 = xor_byte_strings(Y, target)
    c = cipher[:16] + chosen_cn1 + cipher[32:]
    print check(c)

if __name__ == '__main__':
    inject()
