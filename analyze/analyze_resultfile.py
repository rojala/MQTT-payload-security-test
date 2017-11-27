""" xx """
import pickle
import sys
from pprint import pprint

values = []
with open(sys.argv[1], 'rb') as fptr:
    values = pickle.load(fptr)

algorithms = []
for val in values:
    if val["Score"] > -1:
        if val["Alg"] not in algorithms:
            algorithms.append(val["Alg"])

scorecard = {}

for val in values:
    if val["Score"] > -1:
        if val["Score"] not in scorecard:
            scorecard[val["Score"]] = []
        scorecard[val["Score"]].append(val)

#pprint(scorecard)
scorekeys = sorted(scorecard)

print("---------------------------------")
print("---------------------------------")
for sck in scorekeys[:-5]:
    print(scorecard[sck])

print("---------------------------------")
for sck in scorekeys[:10]:
    print(scorecard[sck])

print("---------------------------------")
print("---------------------------------")

for alg in algorithms:
    cnt = 0
    for sck in scorekeys:
        for row in scorecard[sck]:
            if row["Alg"] == alg:
                print(row)
                cnt += 1
            if cnt > 4:
                break
        if cnt > 4:
            break

print("---------------------------------")
print("---------------------------------")

scorekeys = sorted(scorecard, reverse=True)
for alg in algorithms:
    cnt = 0
    for sck in scorekeys:
        for row in scorecard[sck]:
            if row["Alg"] == alg:
                print(row)
                cnt += 1
            if cnt > 4:
                break
        if cnt > 4:
            break
