#!/usr/bin/python

import sys
from tlsutil import *
#import pcap
#import dpkt


def ungrease_one(a):
    if (a & 0x0f0f) == 0x0a0a and (a & 0xf000) >> 8 == (a & 0x00f0):
        return 0x0a0a
    return a

def ungrease(x):
    return map(ungrease_one, x)



def bytea_to_u16s(bya):
    return [ord(bya[2*a])*256 + ord(bya[2*a+1]) for a in xrange(len(bya)/2)]

def bytea_to_u8s(bya):
    return [ord(a) for a in bya]


# Could use struct.parse, but meh. want arbitrary length arrays of base-256 data
def aint(arr):
    s = 0
    for a in arr:
        s *= 256
        s += ord(a)
    return s

fprints = {}

import re
import hashlib
import struct


def get_fingerprint(tls_version, ch_version, cipher_suites, comp_methods, extensions,
        elliptic_curves, ec_point_fmt, sig_algs, alpn):

    def update_arr(h, arr):
        h.update(struct.pack('>L', len(arr)))
        h.update(''.join([chr(a) for a in arr]))

    h = hashlib.sha1()
    h.update(struct.pack('>HH', tls_version, ch_version))

    update_arr(h, cipher_suites)
    update_arr(h, comp_methods)
    update_arr(h, extensions)
    update_arr(h, elliptic_curves)
    update_arr(h, ec_point_fmt)
    update_arr(h, sig_algs)
    update_arr(h, alpn)

    out, = struct.unpack('>q', h.digest()[0:8])
    return out

def dbs(s):
    return '\\x' + ''.join(['%02x' % c for c in s])


#convert lists of u16 to list of u8s
def list_u16_to_u8(l):
    return [u8 for pair in [[u16>>8, u16&0xff] for u16 in l] for u8 in pair]


from prod import db
import random
import time
db = db.get_conn_cur()

db.cur.execute('select count(*), sum(seen) from mv_ranked_fingerprints')
rows = db.cur.fetchall()
total_fps = int(rows[0][0])      # Total number of fingerprints
total_seen = int(rows[0][1])     # Total number of connections seen

utls_ciphers = set([0xcca8,
0xcca9,
0xc02f,
0xc02b,
0xc030,
0xc02c,
0xc027,
0xc013,
0xc023,
0xc009,
0xc014,
0xc00a,
0x009c,
0x009d,
0x003c,
0x002f,
0x0035,
0xc012,
0x000a,
0x0005,
0xc011,
0xc007,
0xcc13,
0xcc14,
0x0a0a,
0x00ff])
utls_weak_ciphers = set([
0xc024,
0xc028,
0x003d
])
utls_comp = set([0x00,])
utls_exts = set([
0x0 ,
0x5 ,
0xa ,
0xb ,
0xd ,
0x10,
0x12,
0x15,
0x17,
0x23,
0x3374,
0xff01, 0x0a0a])
utls_pt_fmt = set([0x00])
utls_sig_algs = set([
    0x0201,
    0x0401,
    0x0501,
    0x0601,
    0x0203,
    0x0403,
    0x0503,
    0x0603,
    ])
utls_curves = set([
    0x0017,
    0x0018,
    0x0019,
    0x001d,
    0x0a0a])
utls_alpn = set() # any alpn supported...

from enum import Enum
class Support(Enum):
    none = 0
    full = 1
    weak = 2

def is_utls_supported(fid, rec_ver, ch_ver, ciphers, comp, exts, curves, pt_fmt, sig_algs, alpn):
    supported = Support.full
    reason = []
    for c in ciphers:
        if c not in utls_ciphers:
            if c in utls_weak_ciphers:
                supported = Support.weak
                reason.append("cipher_weak:%04x"%c)
            else:
                supported = Support.none
                reason.append("cipher:%04x" % c)

    for e in exts:
        if e not in utls_exts:
            supported = Support.none
            reason.append("ext:%04x"%e)
    for c in comp:
        if c not in utls_comp:
            supported = Support.none
            reason.append("comp:%02x"%c)
    for c in curves:
        if c not in utls_curves:
            supported = Support.none
            reason.append("curve:%04x"%c)
    for pt in pt_fmt:
        if pt not in utls_pt_fmt:
            supported = Support.none
            reason.append("pt:%04x"%pt)
    for sig in sig_algs:
        if sig not in utls_sig_algs:
            supported = Support.none
            reason.append("sig:%04x"%sig)
    # Any alpn supported...

    return supported, reason

db.cur.execute('select fingerprints.*, rank, coalesce(seen,0) from fingerprints left join mv_ranked_fingerprints on fingerprints.id=mv_ranked_fingerprints.id')

min_supported_rank = total_fps
min_supported_fp = None
reasons = {}    # str(reason) => (fps, conns) for why fingerprints aren't supported by utls

rows = db.cur.fetchall()
n = 0

fps_supported = 0
conns_supported = 0

unsafe_min_supported_rank = total_fps
unsafe_min_supported_fp = None

unsafe_fps_supported = 0
unsafe_conns_supported = 0

for row in rows:
    fid, rec_ver, ch_ver, ciphers, comp, exts, curves, pt_fmt, sig_algs, alpn, rank, seen, = row


    ciphers = bytea_to_u16s(ciphers)
    comp = bytea_to_u8s(comp)
    exts = bytea_to_u16s(exts)
    curves = bytea_to_u16s(curves)[1:]
    pt_fmt = bytea_to_u8s(pt_fmt)[1:]
    sig_algs = bytea_to_u16s(sig_algs)[2:]
    alpn = bytea_to_u8s(alpn)


    supported, reason = is_utls_supported(fid, rec_ver, ch_ver, ciphers, comp, exts, curves, pt_fmt, sig_algs, alpn)
    if fid ==   -7127967423922852970:
        print supported, reason

    if supported == Support.full:
        fps_supported += 1
        conns_supported += seen
        if rank < min_supported_rank and rank > 0:
            min_supported_rank = rank
            min_supported_fp = fid
    elif supported == Support.weak:
        unsafe_fps_supported += 1
        unsafe_conns_supported += seen
        if rank < unsafe_min_supported_rank and rank > 0:
            unsafe_min_supported_rank = rank
            unsafe_min_supported_fp = fid
    else:
        s_reason = str(reason)
        if s_reason not in reasons:
            reasons[s_reason] = (0, 0, reason)
        fps, conns, _ = reasons[s_reason]
        fps += 1
        conns += seen
        reasons[s_reason] = (fps, conns, reason)

    if n % 10000 == 0:
        print ' --- %d, %d supported' % (n, fps_supported)
    n += 1

print '--------'
print ''
print 'Supported by uTLS:'
print 'Only safe ciphers:'
print '%d fingerprints (%0.3f%%)' %  (fps_supported, 100*float(fps_supported)/total_fps)
print '%d connections (%0.3f%%)' %  (conns_supported, 100*float(conns_supported)/total_seen)
print 'Including weak ciphers:'
print '%d fingerprints (%0.3f%%)' %  (fps_supported + unsafe_fps_supported, 100*float(fps_supported + unsafe_fps_supported)/total_fps)
print '%d connections (%0.3f%%)' %  (conns_supported + unsafe_conns_supported, 100*float(conns_supported + unsafe_conns_supported)/total_seen)
print ''

print 'Top ranked fingerprint: #%s: %s' % (min_supported_rank, min_supported_fp)
print 'Top ranked weak fingerprint: #%s: %s' % (unsafe_min_supported_rank, unsafe_min_supported_fp)
print ''


print '--------'
print 'Some reasons uTLS not supported:'
n = 0
for s_reason, count in sorted(reasons.items(), key=lambda x: x[1][1], reverse=True):
    fps, seen, reason = count
    if len(reason) < 4 and seen > 1000:
        print '%s  %d  %d' % (reason, fps, seen)
    #n += 1
    #if n > 20:
    #break


print '--------'
print 'Some reasons uTLS not supported:'