from util import encrypt_repeating_key_xor
from sys import argv

if __name__ == '__main__':
    with open(argv[1]) as f:
        print encrypt_repeating_key_xor(f.read(), 'ICE').encode('hex')
