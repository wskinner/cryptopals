from util import hamming, single_xor, encrypt_repeating_key_xor

print hamming('this is a test', 'wokka wokka!!!')
keysize = range(2, 41)

# return a list of the top n most likely keysizes
def guess_keysize(data, n=3):
    diffs = []
    for i in keysize:
        b1 = data[:i]
        b2 = data[i:i*2]
        b3 = data[i*2:i*3]
        b4 = data[i*3:i*4]
        dist = (hamming(b1, b2) + hamming(b2, b3) + hamming(b3, b4) + hamming(b4, b2)) / 4.
        diff = (dist / float(i), i)
        diffs.append(diff)
    diffs = sorted(diffs)
    print diffs
    return [x[1] for x in diffs[:n]]

def transpose(data, keysize):
    blocks = []
    for j in range(keysize):
        b = []
        for i in range(j, len(data), keysize):
            b.append(data[i])
        blocks.append(''.join(b))
    return blocks

def solve_block(block):
    letters = set(map(chr, range(65, 123)))
    letters.add(chr(32))
    counts = []
    for i in range(256):
        xored = single_xor(block, chr(i))
        count = float(len([a for a in xored if a in letters])) / len(xored)
        counts.append((count, chr(i)))
    best = [x for x in reversed(sorted(counts))][0]
    return best[1]

if __name__ == '__main__':
    with open('6.txt') as f:
        data = f.read().strip().decode('base64')
        keysizes = guess_keysize(data)
        print keysizes
        for ks in keysizes:
            blocks = transpose(data, ks)
            prev_keys = []
            keys = []
            key = ''
            for block in blocks:
                key += solve_block(block)
            print encrypt_repeating_key_xor(data, key)
