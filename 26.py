from util import *

nonce = 0
key = keygen()
def wrap(data):
    def escape(st):
        return st.replace('=', '%3D').replace(';', '%3B')

    wrapped = "comment1=cooking%20MCs;userdata=" + escape(data) + ";comment2=%20like%20a%20pound%20of%20bacon"
    padded = pkcs7_pad(wrapped)
    return stringify_stream(ctr_encrypt(padded, key, nonce))

def check(enc):
    plain = stringify_stream(ctr_decrypt(enc, key, nonce))
    print plain
    return ';admin=true;' in plain 

# Method:
# We encrypt a known plaintext, allowing us to get the CTR key for that block
# Then we can use the key to encrypt our injected "admin=true" string, and
# splice it into the ciphertext.
def inject():
    target = ';admin=true;aaaa'
    assert len(target) == 16
    pre = "comment1=cooking%20MCs;userdata="
    # This is the index of the block we're going to use
    block_i = len(pre) / 16
    
    # Chosen plaintext
    pn = 16 * 'A'
    cipher = wrap(pn)
    c1 = cipher[block_i * 16: block_i * 16 + 16]
    key = xor_byte_strings(c1, pn)
    chosen_c1 = xor_byte_strings(key, target)
    c = cipher[:block_i * 16] + chosen_c1 + cipher[block_i * 16:]
    print check(c)

if __name__ == '__main__':
    inject()
