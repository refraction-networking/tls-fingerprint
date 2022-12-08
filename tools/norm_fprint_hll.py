import math
import hashlib
from prod import db
from collections import defaultdict

db = db.get_conn_cur()

m = 128  # If updated, need to update h() and estimate()

norm_count = defaultdict(int)    #norm_ext_id => number unique fingerprints (true count)

registers = defaultdict(list)   # norm_ext_id => list of m registers of integer counts

# warning: little endian
def pos(b):
    for i in range(len(b)):
        for j in range(8):
            if (b[i] & (1 << (7-j))) != 0:
                return i*8 + j + 1
    raise Exception('No 1 bits found in %s' % b)
    #return -1


# hardcode m=16
def h16(exts):
    out = bytearray(hashlib.sha256(exts).digest())
    idx = (out[0] & 0xf0) >> 4
    out[0] &= 0x0f
    return idx, pos(out) - 4 # subtract 4, because the first 4 bits were zeroed out

# hardcode m=128
def h128(exts):
    out = bytearray(hashlib.sha256(exts).digest())
    idx = (out[0] & 0xfe) >> 1
    out[0] &= 0x01
    return idx, pos(out) - 7 # subtract 7, because the first 4 bits were zeroed out


db.cur.execute('''select id, norm_ext_id, extensions from fingerprint_map''')
for row in db.cur.fetchall():
    fid, nfid, exts = row
    exts = bytearray(exts)

    # Update true count
    norm_count[nfid] += 1

    # Now do it for HLL :P
    regs = registers[nfid]
    if len(regs) != m:
        regs = [0]*m
    
    ridx, p = h128(exts)
    regs[ridx] = max(regs[ridx], p)

    registers[nfid] = regs

def estimate(regs):
    #a_m = 0.673 # for m=16, from https://en.wikipedia.org/wiki/HyperLogLog
    a_m = 0.7213 / (1+(1.079/m))
    Z = 1.0 / sum([2**-r for r in regs])
    est = a_m * m*m * Z
    if est < (2.5*m):
        V = sum([x==0 for x in regs])
        return m*math.log(m / V)
    return est

for nfp in norm_count.keys():
    est = estimate(registers[nfp])
    actual = norm_count[nfp]
    err = abs(est-actual)/actual
    print('%s %d %.2f %.6f %s' % (nfp, actual, est, err, registers[nfp]))

