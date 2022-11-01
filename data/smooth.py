#!/usr/bin/python

import sys
import csv

WIN = 24
EXPECT_JUMP = True


fn = sys.argv[1]
data = []
with open(fn, 'r') as f:
    reader = csv.reader(f)
    for line in reader:
        t, value = line
        try:
            t = int(t)
            value = float(value)
        except:
            continue

        data.append((t, value))



smoothed = [(data[i][0], data[i][1], sum([a[1] for a in data[i:i+WIN]])/float(WIN)) for i in xrange(len(data)-WIN+1)]

prev_t = 0
for t, v, s in smoothed:
    if t != prev_t + 3600:
        print ''
    print '%d,%d,%d' % (t, v, s)
    prev_t = t



