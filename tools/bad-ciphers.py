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

db.cur.execute('select sum(seen) from mv_ranked_fingerprints')
rows = db.cur.fetchall()
total_seen = int(rows[0][0])

#db.cur.execute('select * from fingerprints where cipher_suites=extensions')
#db.cur.execute('select * from fingerprints limit 10')
db.cur.execute('select fingerprints.*, rank, coalesce(seen,0) from fingerprints left join mv_ranked_fingerprints on fingerprints.id=mv_ranked_fingerprints.id')

rows = db.cur.fetchall()

bad_ciphers = {}
bad_exts = {}

bad_fps = set()

min_rank = 1000000
min_fid = 0
bad_seen = 0

legacy_ciphers = set([
    0xcc13, # "LEGACY_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    0xcc14, # "LEGACY_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    0xcc15, # "LEGACY_TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    ])
legacy_fps = set()
legacy_seen = 0

gost_ciphers = set([
  0x0080, #: "TLS_GOSTR341094_WITH_28147_CNT_IMIT",
  0x0081, #: "TLS_GOSTR341001_WITH_28147_CNT_IMIT",
  0x0082, #: "TLS_GOSTR341094_WITH_NULL_GOSTR3411",
  0x0083, #: "TLS_GOSTR341001_WITH_NULL_GOSTR3411",
  0xff85, #: "TLS_GOSTR341112_256_WITH_28147_CNT_IMIT",
  0xff87, #: "TLS_GOSTR341112_256_WITH_NULL_GOSTR3411",
])
gost_fps = set()
gost_seen = 0


ssl_ciphers = set([
  0xff80, #: "SSL_RSA_WITH_RC2_CBC_MD5",
  0xff81, #: "SSL_RSA_WITH_IDEA_CBC_MD5",
  0xff82, #: "SSL_RSA_WITH_DES_CBC_MD5",
  0xff83, #: "SSL_RSA_WITH_3DES_EDE_CBC_MD5",
  0x001c, #: "SSL_FORTEZZA_KEA_WITH_NULL_SHA",
  0x001d, #: "SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA",
  0x001e, #: "SSL_FORTEZZA_KEA_WITH_RC4_128_SHA",
  0xfefe, #: "SSL_RSA_FIPS_WITH_DES_CBC_SHA",
  0xfeff, #: "SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA",
  0xffe0, #: "SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA",
  0xffe1, #: "SSL_RSA_FIPS_WITH_DES_CBC_SHA",
])
ssl_fps = set()
ssl_seen = 0

tls13_ciphers = set([
  0x1301, #: "TLS_AES_128_GCM_SHA256",
  0x1302, #: "TLS_AES_256_GCM_SHA384",
  0x1303, #: "TLS_CHACHA20_POLY1305_SHA256",
  0x1304, #: "TLS_AES_128_CCM_SHA256",
  0x1305, #: "TLS_AES_128_CCM_8_SHA256",
])
tls13_fps = set()
tls13_seen = 0



ext_rnd_exts = set([40])
ext_rnd_fps = set()
ext_rnd_seen = 0

# draft 23
tls13_exts = set([
  41, #: "pre_shared_key",
  42, #: "early_data",
  43, #: "supported_versions",
  44, #: "cookie",
  45, #: "psk_key_exchange_modes",
  47, #: "certificate_authorities",
  48, #: "old_filters",
  49, #: "post_handshake_auth",
  50, #: "signature_algorithms_cert",
  51, #: "key_share",
  ])
tls13_ext_fps = set()
tls13_ext_seen = 0

legacy_exts = set([
  0x5500, #: "LEGACY_token_binding",    # https://community.qualys.com/thread/15849
  0x754f, #: "LEGACY_ChannelID",
  35655, #:  "LEGACY_padding",          # https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/NSS_3.15.5_release_notes
  ])
legacy_ext_fps = set()
legacy_ext_seen = 0




unknown_ciphers_fps = set()
unknown_ciphers_seen = 0

unknown_exts_fps = set()
unknown_exts_seen = 0

# Given a cipher (or ext) id, known_set=a set of known ciphers (or exts) ids
# a fingerprint id, the number of times it was seen, and a known_fps_set,
# this will: see if n is in the known_set. if it is, add fid to the known_fps_set
# if fid was not yet in known_fps_set, return seen ( should be added to known_seen)
def add_known(n, known_set, fid, seen, known_fps_set):
    ret = 0
    if n in known_set:
        if fid not in known_fps_set:
            ret = seen
            known_fps_set.add(fid)
    return ret



strict_std_ciphers = dict(cipher_dict)

non_std_ciphers = legacy_ciphers.union(gost_ciphers).union(ssl_ciphers).union(tls13_ciphers)
for nsc in non_std_ciphers:
    del strict_std_ciphers[nsc]

non_std_ciphers_fps = set()
non_std_ciphers_seen = 0


strict_std_exts = dict(ext_dict)
non_std_exts = tls13_exts.union(legacy_exts).union(ext_rnd_exts)
for nse in non_std_exts:
    del strict_std_exts[nse]
non_std_exts_fps = set()
non_std_exts_seen = 0

non_std_fps = set()
non_std_seen = 0


md5_sigalg_fps = set()
md5_sigalg_seen = 0

sha1_sigalg_fps = set()
sha1_sigalg_seen = 0

uniq_cs = set()

for row in rows:
    fid, rec_ver, ch_ver, ciphers, comp, exts, curves, pt_fmt, sig_algs, alpn, rank, seen, = row


    ciphers = bytea_to_u16s(ciphers)
    comp = bytea_to_u8s(comp)
    exts = bytea_to_u16s(exts)
    curves = bytea_to_u16s(curves)
    pt_fmt = bytea_to_u8s(pt_fmt)
    sig_algs = bytea_to_u16s(sig_algs)
    alpn = bytea_to_u8s(alpn)


    for c in ciphers:
        if seen > 1:
            uniq_cs.add(c)
        if c not in cipher_dict:
            #print '%d - cipher %04x' % (fid, c)
            if fid not in bad_fps:
                if rank is not None and rank < min_rank:
                    min_rank = rank
                    min_fid = fid
                bad_seen += int(seen)
            bad_fps.add(fid)
            if c not in bad_ciphers:
                bad_ciphers[c] = (0, 0)

            a, b = bad_ciphers[c]
            bad_ciphers[c] = (a+1, int(b+seen))
            if fid not in unknown_ciphers_fps:
                unknown_ciphers_fps.add(fid)
                unknown_ciphers_seen += int(seen)

        if c not in strict_std_ciphers:
            if fid not in non_std_ciphers_fps:
                non_std_ciphers_fps.add(fid)
                non_std_ciphers_seen += int(seen)

            if fid not in non_std_fps:
                non_std_fps.add(fid)
                non_std_seen += int(seen)

        legacy_seen += add_known(c, legacy_ciphers, fid, seen, legacy_fps)
        gost_seen += add_known(c, gost_ciphers, fid, seen, gost_fps)
        ssl_seen += add_known(c, ssl_ciphers, fid, seen, ssl_fps)
        tls13_seen += add_known(c, tls13_ciphers, fid, seen, tls13_fps)



    for e in exts:
        if e not in ext_dict:
            #print '%d - ext %04x' % (fid, e)
            if fid not in bad_fps:
                if rank is not None and rank < min_rank:
                    min_rank = rank
                    min_fid = fid
                bad_seen += int(seen)
            bad_fps.add(fid)
            if e not in bad_exts:
                bad_exts[e] = (0, 0)
            a, b = bad_exts[e]
            bad_exts[e] = (a+1, int(b+seen))
            if fid not in unknown_exts_fps:
                unknown_exts_fps.add(fid)
                unknown_exts_seen += int(seen)
        if e not in strict_std_exts:
            if fid not in non_std_exts_fps:
                non_std_exts_fps.add(fid)
                non_std_exts_seen += int(seen)

            if fid not in non_std_fps:
                non_std_fps.add(fid)
                non_std_seen += int(seen)

        legacy_ext_seen += add_known(e, legacy_exts, fid, seen, legacy_ext_fps)
        tls13_ext_seen += add_known(e, tls13_exts, fid, seen, tls13_ext_fps)
        ext_rnd_seen += add_known(e, ext_rnd_exts, fid, seen, ext_rnd_fps)


    if len(sig_algs) > 1 and (len(sig_algs)*2-2) == sig_algs[0]:

        for sa in sig_algs[1:]:
            h = (sa>>8) & 0xff
            s = sa & 0xff
            if h == 1:  # MD5
                if fid not in md5_sigalg_fps:
                    md5_sigalg_fps.add(fid)
                    md5_sigalg_seen += int(seen)
            elif h == 2: # SHA1
                if fid not in sha1_sigalg_fps:
                    sha1_sigalg_fps.add(fid)
                    sha1_sigalg_seen += int(seen)




print '%d unique cipher suite values seen' % (len(uniq_cs))
print '%d fingerprints, accounting for %d occurances (%0.3f%%)' % (len(bad_fps), bad_seen, 100*float(bad_seen)/total_seen)
print '%d non-standard fingerprints, %d occurances (%0.3f%%)' % (len(non_std_fps), non_std_seen, 100*float(non_std_seen)/total_seen)
#print '(most seen is rank %d at %d)' % (min_rank, min_fid)

#unknown_ciphers_fp = sum([a[0] for a in bad_ciphers.values()])

print '========='
print 'ciphers'
print '========='
print '   & Fingerprints & \%% Connections \hline'
print 'TLS 1.3 draft ciphers &  %d & %0.3f%%' % (len(tls13_fps), 100*float(tls13_seen)/total_seen)
print 'Legacy ciphers &  %d & %0.3f%%' % (len(legacy_fps), 100*float(legacy_seen)/total_seen)
print 'GOST ciphers &  %d & %0.3f%%' % (len(gost_fps), 100*float(gost_seen)/total_seen)
print 'Outdated SSL ciphers &  %d & %0.3f%%' % (len(ssl_fps), 100*float(ssl_seen)/total_seen)
print 'Unknown ciphers & %d & %0.3f%%' % (len(unknown_ciphers_fps), 100*float(unknown_ciphers_seen)/total_seen)
print 'Total non-standard ciphers & %d & %0.3f%%' % (len(non_std_ciphers_fps), 100*float(non_std_ciphers_seen)/total_seen)


print '----'
print 'TLS 1.3 draft extensions & %d & %0.3f\\%%' % (len(tls13_ext_fps), 100*float(tls13_ext_seen)/total_seen)
print 'Legacy Extensions & %d & %0.3f\\%%' % (len(legacy_ext_fps), 100*float(legacy_ext_seen)/total_seen)
print 'Extended Random & %d & %0.3f\\%%' % (len(ext_rnd_fps), 100*float(ext_rnd_seen)/total_seen)
print 'Unknown extensions & %d & %0.3f\\%%' % (len(unknown_exts_fps), 100*float(unknown_exts_seen)/total_seen)
print 'Total non-standard extensions & %d & %0.3f\\%%' % (len(non_std_exts_fps), 100*float(non_std_exts_seen)/total_seen)


print '----'
print 'Bad sigalgs:'
print 'MD5 & %d & %0.3f\\%%' % (len(md5_sigalg_fps), 100*float(md5_sigalg_seen)/total_seen)
print 'SHA1 & %d & %0.3f\\%%' % (len(sha1_sigalg_fps), 100*float(sha1_sigalg_seen)/total_seen)



print '========='
print 'Unknown Ciphers'
print '========='
for c, count in sorted(bad_ciphers.items(), key=lambda x: x[1][0], reverse=True):
    print '%04x   % 8d  % 9d (%0.4f%%)' % (c, count[0], count[1],100* float(count[1])/total_seen)


print '========='
print 'Unknown extensions'
print '========='
for e, count in sorted(bad_exts.items(), key=lambda x: x[1][0], reverse=True):
    print '%04x   % 8d  % 9d (%0.4f%%)' % (e, count[0], count[1], 100*float(count[1])/total_seen)


