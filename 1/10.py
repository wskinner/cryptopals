from util import cbc_decrypt

with open('10.txt') as f:
    print cbc_decrypt(f.read().strip().decode('base64'), 'YELLOW SUBMARINE', chr(0) * 16, 16)
