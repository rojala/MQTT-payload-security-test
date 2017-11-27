import hexdump
import random
from pprint import pprint


def fill_random_data(amount, range_start=0, range_end=9):
    ret = []
    for indx in range(0, amount):
        rval = random.randint(range_start, range_end)
        ret.append(rval)
    return ret

class analyze_randomness:
    def __init__(self, weight_in_column_multiplier=10, weight_in_row_multiplier=2):
        self.container = []
        self.weight_in_row_multiplier = weight_in_row_multiplier
        self.weight_in_column_multiplier = weight_in_column_multiplier

    def add(self, data):
        self.container.append(data)

    def print(self):
        pprint(self.container)

    def analyze(self):
        ret = 0
        max_rounds = 0
        if 1 < len(self.container):
            max_rounds = len(self.container[0])
        else:
            return 0
        for rnd in range(2, max_rounds, 2):
            if (max_rounds % rnd) == 0:
                ret += self.value_in_same_location(rnd, rnd * 10, rnd * self.weight_in_row_multiplier)
        return ret

    def test_values(self, values, weight, in_same_column=True):
        cnt = 0
        if 2 > len(values):
            return 0
        if in_same_column:
            for val in values[1:]:
                for indx in range(0,len(val)):
                    if values[0][indx] == val[indx]:
                        cnt += weight
        else:
            for start in values[0]:
                for later in values[1:]:
                    if start in later:
                        cnt += weight

        return cnt

    def value_in_same_location(self, value_length, weight_same_row, weight_in_row):
        test = []
        ret = 0
        for val in self.container:
            tst = hexdump.dump(bytes(val), value_length*2, " ")
            test.append(tst.split(" ")) # Create chunks of desired length
        
        for rows in range(0, len(test)):
            ret += self.test_values(test[rows:], weight_same_row, True)

        for rows in range(0, len(test)):
            ret += self.test_values(test[rows:], weight_in_row, False)

        return ret

def test():
    anal_rand = analyze_randomness(10, 2)

    for i in range(0, 200):
        rval = fill_random_data(50, 0, 255)
        anal_rand.add(rval)

    #anal_rand.print()
    print(anal_rand.analyze())

if __name__ == "__main__":
    test()