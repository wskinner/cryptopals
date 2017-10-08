from util import *

def solve_block(block):
    letters = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ ,\'-!?/"')
    counts = []
    for i in range(256):
        xored = single_xor(block, chr(i))
        count = float(len([a for a in xored if a in letters])) / len(xored)
        counts.append((count, chr(i)))
    best = [x for x in reversed(sorted(counts))][0]
    return best[1]

# Make blocks by taking the first byte of every line, the 
# second byte of every line, and so on.
def transpose(data, keysize):
    blocks = []
    for i in range(keysize):
        blocks.append(''.join([line[i] for line in data]))

    return blocks

if __name__ == '__main__':

    assert transpose(['h', 'e', 'l', 'l', 'o'], 1) == ['hello']
    with open('20.txt') as f:
        enc = [line.decode('base64') for line in f]
        keysize = min([len(x) for x in enc])

        blocks = transpose(enc, keysize)

        key = ''
        for block in blocks:
            key += solve_block(block)

        for line in enc:
            print xor_byte_strings(key, line)
