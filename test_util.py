from util import *

def test_num_to_str():
    inputs = [
            'Hello World',
            '',
            '    ',
            ]
    for i in inputs:
        assert num_to_str(str_to_num(i)) == i

test_num_to_str()
