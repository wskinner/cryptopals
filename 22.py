import time
from util import MersenneTwister as MyRandom
import random

def func():
    time.sleep(random.randint(40, 1000))
    my_rand = MyRandom(int(time.time()))
    time.sleep(random.randint(40, 1000))
    return my_rand.extract_number()

def break_range(start, end, output):
    for t in xrange(start, end):
        r = MyRandom(t).extract_number()
        if output == r: return t

if __name__ == '__main__':
    start = int(time.time())
    num = func()
    end = int(time.time())

    seed = break_range(start, end, num)
    print 'The seed is', seed
