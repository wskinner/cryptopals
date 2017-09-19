import numpy as np
from util import MersenneTwister

if __name__ == '__main__':
    mt = MersenneTwister(0)
    nprand = np.random.RandomState(0)
    for i in range(10000):
        assert mt.extract_number() == nprand.randint(0, 0xFFFFFFFF)
        assert mt.extract_number() == nprand.randint(0, 0xFFFFFFFF)
        assert mt.extract_number() == nprand.randint(0, 0xFFFFFFFF)
        assert mt.extract_number() == nprand.randint(0, 0xFFFFFFFF)
