from util import *
from collections import Counter

data = '''
SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==
Q29taW5nIHdpdGggdml2aWQgZmFjZXM=
RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==
RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=
SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk
T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==
T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=
UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==
QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=
T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl
VG8gcGxlYXNlIGEgY29tcGFuaW9u
QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==
QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=
QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==
QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=
QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=
VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==
SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==
SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==
VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==
V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==
V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==
U2hlIHJvZGUgdG8gaGFycmllcnM/
VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=
QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=
VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=
V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=
SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==
U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==
U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=
VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==
QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu
SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=
VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs
WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=
SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0
SW4gdGhlIGNhc3VhbCBjb21lZHk7
SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=
VHJhbnNmb3JtZWQgdXR0ZXJseTo=
QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=
'''.strip().split('\n')
data = [d.strip() for d in data]

key = keygen(16, 0)
decoded = [x.decode('base64') for x in data]
encrypted = [stringify_stream(ctr_encrypt(x, key, 0)) for x in decoded]
encrypted_blocks = [get_blocks(enc) for enc in encrypted]

# If we know search_st appears somewhere in the plaintext, we can guess various
# places it could be, and then try decrypting with the keystream we get from placing it at 
# that point. For each place the search string could go, we generate 1 or 2 candidate
# keystream blocks, with 0x00 bytes as placeholders on either side. e.g. if 
# we found a candidate for ['???ice ice baby?'], then we produce a tuple 
# (3, 'ice ice baby', 1) signifying 3 unknown bytes, 12 known bytes, and 1 unknown byte.
def generate_keystreams(search_st):
    # possible keystream blocks counts for each keystream block
    # for each block index i, candidate key block -> count of 
    keystream_counts = []
    for ct in encrypted:
        blocks = get_blocks(ct)
        if len(blocks) > len(keystream_counts):
            keystream_counts += [Counter() for i in range(len(blocks) - len(keystream_counts))]
            
# for each possible alignment of the search phrase in enc, print
# the decrypted result of all blocks, using the keystream block that results
# from that alignment
def candidates(search_st, enc):
    for i in range(len(enc) - len(search_st)):
        block1 = i / 16
        start_block_index = i % 16
        block2 = (i + len(search_st)) / 16

        if block1 == block2:
            padded = chr(0) * start_block_index + search_st + chr(0) * (16 - len(search_st) - start_block_index)
            assert len(padded) == 16
            print i
            blocks = [en[block1] for en in encrypted_blocks if block1 < len(en)]
            dec = [xor_byte_strings(padded, e) for e in blocks]
            print dec
        else:
            end_block_index = (i + len(search_st)) % 16
            candidate = xor_byte_strings(search_st, enc[i:i+16])

# return a list containing the byte at index from each payload xored
# with the given byte
def guess_keystream_byte(index, ch):
    result = []
    for e in encrypted:
        if index < len(e):
            result.append(xor_byte_strings(ch, e[index]))
        else:
            result.append('')
    return result

def guess_keystream_prefix(index, prefix):
    return [xor_byte_strings(prefix, e[index:index+len(prefix)]) for e in encrypted]

# guess that the plaintext of index byte of enc_index line is ch
def guess_plaintext_byte(index, enc_index, ch):
    for i in range(256):
        b = xor_byte_strings(encrypted[enc_index][index], chr(i))
        if b == ch:
            return i, guess_keystream_byte(index, chr(i))

def count_chars(ls, charset):
    count = 0
    for c in ls:
        if c in charset: count += 1
    return count

# Candidates is a list of lists. Each list maps encrypted line number to the next
# byte for that line. There is a list for each decryption possibility with high enough
# likelihood.
# Current contains one list for each encrypted row. Each list contains one string for
# each decryption possibility.
def update(current, candidates):
    #print 'update', current, candidates
    new = [[] for i in range(len(current))]
    for i, strings in enumerate(current):
        for st in strings:
            for c in candidates:
                new[i].append(st + c[i])
    return new

def prune(current, row, st):
    for i, s in enumerate(current[row]):
        if s == st:
            print '!!!!!!!!!!!!!!!'
            break
    newnew = []
    for cands in current:
        newnew.append([cands[i]])
    print 'old length', sum([len(x) for x in current])
    print 'new length', sum([len(x) for x in newnew])
    return newnew

# Algorithm: generate candidate keystreams by xoring plaintext guesses
# against ciphertexts. Then print out the result of decrypting the ciphertexts 
# with that keystream.
if __name__ == '__main__':
    #for c in range(256):
    #    print c, guess_keystream_byte(20, chr(c))
    #exit(0)
    #print guess_plaintext_byte(10, 1, 'h')
    likely_chars = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ ,\'-\n!?')
    candidate_lines = [[''] for i in range(len(encrypted))]
    for index in range(max([len(l) for l in encrypted])):
        st = 'I have met them at close of day'
        if index < len(st):
            candidate_lines = prune(candidate_lines, 0, st[index])
        candidates = []
        best = []
        for i in range(256):
            result = guess_keystream_byte(index, chr(i))
            if all([c in likely_chars for c in result]):
                candidates.append(result)
            best.append(result)
        if len(candidates) == 0:
            best = [x for x in reversed(sorted(best, key=lambda x: count_chars(x, likely_chars)))]
            if index < 27:
                candidates.extend(best[:3])
            else:
                candidates.extend(best[:3])
                
        candidate_lines = update(candidate_lines, candidates)

    # Possible plaintext lines for the first encrypted line, the second, and so on

    for l in candidate_lines:
        print l
            
    exit(0)
    search_st = 'Ice'
    #for enc in encrypted:
    #    candidates(search_st, enc)
    index = 2
    guesses = [(i, guess_keystream_byte(index, chr(i))) for i in range(256)]
    ranked = [x for x in reversed(sorted(guesses, key=lambda tup: count_chars(tup[1], likely_chars)))]

    keystream = [133, 100, 81, 226, 193, 25]
    best_guesses = []
    for i in range(65, 91):
        for j in likely_chars:
            for k in likely_chars:
                keystream = [i, j, k]
                prefix = ''.join([chr(i) for i in keystream])
                prefix_guesses = guess_keystream_prefix(0, prefix)
                joined = ''.join(prefix_guesses)
                count = count_chars(joined, likely_chars)
                if count / float(len(joined)) > .8:
                    best_guesses.append(keystream)
    print best_guesses

    #print prefix_guesses
    #for x in ranked[:5]:
    #    print x

    #print 'plaintext guess'
    #print guess_plaintext_byte(index, 0, 'e')

