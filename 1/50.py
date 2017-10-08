from util import *

if __name__ == '__main__':
    key = 'YELLOW SUBMARINE'
    iv = '\x00' * 16
    msg = pkcs7_pad("alert('MZA who was that?');\n")
    assert cbc_mac(msg, key, iv).encode('hex') == '296b8d7cb78a243dda4d0a61d33bbdd1'

    # Idea: find valid js prefix for the above, s.t. cbc(block[-2]) xor block -1 == 00.
    # could end in // to make the above a comment.
    # c1, c2 = cbc_encrypt(msg, key, iv) implies 
    # cbc_encrypt(c1 xor msg[16:], key, iv) == cbc_mac(msg, key, iv)
    
    msg2 = "alert('Ayo, the Wu is back!');//"
    # Define T to be the block described above, so T xor msg[:16] == c1
    # T = c1 xor msg[:16]
    # The full payload looks like:  msg2 || T || msg[16:]
    # Let mc = cbc_mac(msg2, key, iv), which is used as the iv for T || msg[16:]
    # We choose T = mc xor msg[:16]

    c = cbc_encrypt_nopad(msg, key, iv)
    c1, c2 = c[:16], c[16:]
    mc = cbc_mac(msg2, key, iv)
    T = xor_byte_strings(mc, msg[:16])
    assert xor_byte_strings(T, mc) == msg[:16]

    payload = msg2 + T + msg[16:]
    assert cbc_mac(payload, key, iv) == cbc_mac(msg, key, iv)
    print 'Copy paste into chrome to test', payload
