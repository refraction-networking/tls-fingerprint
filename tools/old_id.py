#!/usr/bin/python

from parsepcap import Fingerprint

from prod import db
import struct
import sys


def bytea_to_u16s(bya):
    return [ord(bya[2*a])*256 + ord(bya[2*a+1]) for a in xrange(len(bya)/2)]

def bytea_to_u8s(bya):
    return [ord(a) for a in bya]

def hid(nid):
    return struct.pack('!q', nid).encode('hex')

# Could use struct.parse, but meh. want arbitrary length arrays of base-256 data
def aint(arr):
    s = 0
    for a in arr:
        s *= 256
        s += ord(a)
    return s


db = db.get_conn_cur()


if len(sys.argv) < 2:
    print 'Usage: %s hex_id' % sys.argv[0]
    sys.exit(0)

hex_id = sys.argv[1]
nid, = struct.unpack('!q', hex_id.decode('hex'))

db.cur.execute('select * from fingerprints left join mv_ranked_fingerprints on fingerprints.id=mv_ranked_fingerprints.id where fingerprints.id=%s', ([nid]))


for row in db.cur.fetchall():
    fpid, tls_version, ch_version, ciphers, comp_methods, exts, named_groups, ec_pt_fmt,\
        sig_algs, alpn, key_share, psk_key_ex_modes, supported_versions, cert_comp_algs,\
        record_size_limit, _, seen, rank = row


    fp = Fingerprint(tls_version, ch_version, bytea_to_u8s(ciphers), bytea_to_u8s(comp_methods),\
		bytea_to_u8s(exts), bytea_to_u8s(named_groups), bytea_to_u8s(ec_pt_fmt),\
 		bytea_to_u8s(sig_algs), bytea_to_u8s(alpn),\
                bytea_to_u8s(key_share), bytea_to_u8s(psk_key_ex_modes),\
		bytea_to_u8s(supported_versions), bytea_to_u8s(cert_comp_algs),\
                bytea_to_u8s(record_size_limit))

    new_id = fp.get_fingerprint()

    old_id = fp.get_fingerprint_v1()

    print 'Old ID: %s   %d' % (hid(old_id), old_id)
    print 'New ID: %s   %d' % (hid(new_id), new_id)


