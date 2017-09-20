from util import MersenneTwister

class MTUntemper:

    def __init__(self):
        self.state = []

    # Given x = y ^ (y >> shift_bits), return y
    def unshift_right(self, x, shift_bits):
        return x ^ (x >> shift_bits)

    def unshift_right2(self, x, shift):
        i = 0
        result = 0
        while i * shift < 32:
            # results in shift - i 1s followed by 32 - shift 1s
            partial_mask = self.srl((-1 << (32 - shift)), shift * i)

    def unshift_left_xor(self, x, shift_bits, mask):
        pass

    def srl(self, x, shift_bits): return val >> n if val >= 0 else (val + 0x100000000) >> n

    def update(self, y):
        # untemper stage 4
        y = y ^ (y >> 18)

        # untemper stage 3
        y = y ^ (y << 15) & 0xefc60000

        # untemper stage 2
        a = y ^ (y << 7) & 0x9d2c5680
        b = y ^ (a << 7) & 0x9d2c5680
        c = y ^ (b << 7) & 0x9d2c5680
        d = y ^ (c << 7) & 0x9d2c5680
        y = y ^ (d << 7) & 0x9d2c5680

        # untemper stage 1
        a = y ^ (y >> 11)
        y = y ^ (a >> 11)

        self.state.append(y)

if __name__ == '__main__':
    mt = MersenneTwister(0)
    mtu = MTUntemper()
    for i in range(624):
        mtu.update(mt.randint())

    mt2 = MersenneTwister(0)
    mt2.mt = mtu.state
    mt2.index = 624 * 2

    for i in xrange(1000):
        assert mt.randint() == mt2.randint()
