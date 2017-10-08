# 65-90, 97-122 are letters
from util import single_xor, guess_single_xor_key
letters = set(map(chr, range(97, 123)))

# Produces 'Now that the party is jumping'
for encoded in open('4_input.txt'):
    encoded = encoded.strip()
    counts = []
    for i in range(256):
        xored = single_xor(encoded.decode('hex'), chr(i))
        count = float(len([a for a in xored if a in letters])) / len(xored)
        counts.append((count, xored))
    best = [x for x in reversed(sorted(counts))][0]
    if best[0] > .6: print best[1]
