from util import single_xor
encoded = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'

# Produces 'Cooking MC's like a pound of bacon'
if __name__ == '__main__':
    for i in range(256):
        xored = single_xor(encoded.decode('hex'), chr(i))
        print xored
