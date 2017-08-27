from collections import Counter

def detect_ecb(data, blocksize=16):
    counts = Counter()
    for i in range(0, len(data) - blocksize):
        block = ''.join(data[i:i+blocksize])
        counts[block] += 1

    return counts.most_common(1)[0][1] / float(len(data) - blocksize)

with open('8.txt') as f:
    counts = []
    for line in f:
        line = line.strip()
        data = line.decode('hex')
        counts.append((detect_ecb(data), line))

    print list(reversed(sorted(counts)))[:2]
