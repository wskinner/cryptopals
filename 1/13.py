from util import *

key = keygen()

# Provided to the attacker
def encrypt_user_profile(encoded):
    return ecb_encrypt(encoded, key)

def decrypt_user_profile(enc):
    return parse_kv(ecb_decrypt(enc, key))

# If we have ciphertext for 'blahemail=admin@blah' aligned so that
# blah
# input 1: 'foo@bar.comaaa' -> b1: 'email=foo@bar.co' b2: 'maaa&uid=1&role=' b3: 'user' + padding
# input 2: '          admin'  + 11 bytes of char 11 to simulate pkcs7 padding -> 
# b1: email=           b2: admin           b3: &uid=blah
# Want 1[b1] + 1[b2] + 2[b2]
def make_admin_profile():
    e1 = encrypt_user_profile(profile_for('foo@bar.comaaa'))
    e2 = encrypt_user_profile(profile_for('          admin' + chr(11) * 11))
    cnp = e1[:32] + e2[16:32]
    print decrypt_user_profile(cnp)

if __name__ == '__main__':
    #print profile_for('foo@bar.com')
    make_admin_profile()
