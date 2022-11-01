#!/usr/bin/python

import sys
import pcap
import dpkt
import os



PRINT_SQL = False
DO_SQL = True

if DO_SQL:
    from prod import db
    db = db.get_conn_cur()


def ungrease_one(a):
    if (a & 0x0f0f) == 0x0a0a and (a & 0xf000) >> 8 == (a & 0x00f0):
        return 0x0a0a
    return a

def ungrease(x):
    return map(ungrease_one, x)


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


def add_fingerprint(name, tls_version, ch_version, cipher_suites, comp_methods, exts, curves, pt_fmts, sig_algs, alpn):
    global fprints, PRINT_SQL
    #r = re.compile('([a-z]+)([0-9]+)\_[0-9]+([a-z0-9]+)')  #fingerprints2
    #r = re.compile('([a-z]+)([0-9]+)\_([a-z0-9]+)')    # fingerprints5
    #matches = r.match(sni_host)
    #if matches is None:
    #    raise Exception('%s has no match' % sni_host)
    #browser = matches.group(1)
    #version = matches.group(2)
    #os = matches.group(3)

    #if os == 'windows7':
    #    os = 'win7'
    #elif os == 'osxsierra':
    #    os = 'osx'

    f = get_fingerprint(tls_version, ch_version, cipher_suites, comp_methods, exts, curves,\
                pt_fmts, sig_algs, alpn)
    #f = '(%s, %s, %s, %s, %s, %s, %s, %s, %s)' % (tls_version, ch_version, cipher_suites, comp_methods, exts, curves, pt_fmts, sig_algs, alpn)
    if f not in fprints:
        fprints[f] = set()
    #b = '%s_%s_%s' % (browser, version, os)
    print '%s: %s' % (name, f)

    # DB insert
    if PRINT_SQL:
        print "  INSERT INTO fingerprints (id, record_tls_version, ch_tls_version, cipher_suites, compression_methods, extensions, eliptic_curves, ec_point_fmt, sig_algs, alpn) VALUES (%d, %d, %d, '%s', '%s', '%s', '%s', '%s', '%s', '%s');" %\
            (f, tls_version, ch_version, dbs(cipher_suites), dbs(comp_methods), dbs(exts), dbs(curves), dbs(pt_fmts), dbs(sig_algs), dbs(alpn))

    if DO_SQL:
        # Check if we even care about this fingerprint
        db.cur.execute('select count(*) from fingerprints where id=%s', [f])
        rows = db.cur.fetchall()
        if rows[0][0] == 0:
            print 'Have not heard of fingerprint %d...' % f
            return

        # we care, insert it
        # lookup or create label ID
        db.cur.execute('select lid from labels where label=%s', [name])
        rows = db.cur.fetchall()
        lid = 0
        if len(rows) == 0:
            # new label
            db.cur.execute('insert into labels (label) VALUES (%s)', [name])
            #lid = int(db.cur.lastrowid) #doesn't work, some of the time...ugh

            db.conn.commit()
            db.cur.execute('select lid from labels where label=%s', [name])
            rows = db.cur.fetchall()
            lid = int(rows[0][0])
            print '+ Made label %d for "%s"' % (lid, name)
        else:
            lid = int(rows[0][0])

        if lid == 0:
            print 'Error: bad lid for fp %d and label "%s"' % (f, name)
            return

        db.cur.execute('select * from fingerprint_labels where fid=%s and lid=%s', [f, lid])
        rows = db.cur.fetchall()
        if len(rows) > 0:
            # Already have this...
            return

        db.cur.execute('insert into fingerprint_labels (fid, lid) VALUES (%s, %s)', [f, lid])
        db.conn.commit()


    return

#convert lists of u16 to list of u8s
def list_u16_to_u8(l):
    return [u8 for pair in [[u16>>8, u16&0xff] for u16 in l] for u8 in pair]


def parse_pcap(name, pcap_fname):
    p = pcap.pcap(pcap_fname)
    for ts, pkt in p:
        try:
            eth = dpkt.ethernet.Ethernet(pkt)
            if eth.type != dpkt.ethernet.ETH_TYPE_IP:
                continue
        except dpkt.dpkt.NeedData:
            eth = dpkt.sll.SLL(pkt)
            if eth.ethtype != dpkt.ethernet.ETH_TYPE_IP:
                continue

        ip = eth.data
        if ip.p != dpkt.ip.IP_PROTO_TCP:
            continue
        tcp = ip.data
        if tcp.dport != 443:
            continue

        # Look for client hello
        tls = tcp.data
        if len(tls) == 0:
            continue
        if tls[0] != '\x16':
            # Not a handshake
            continue
        tls_version = aint(tls[1:3])
        tls_len = aint(tls[3:5])
        hs_type = tls[5]
        if hs_type != '\x01':
            # not a client hello
            continue

        # Parse client hello
        chello_len = aint(tls[6:9])
        chello_version = aint(tls[9:11])
        rand = tls[11:11+32]
        off = 11+32

        # session ID
        sess_id_len = aint(tls[off])
        off += 1 + sess_id_len

        #print 'sess_id len %d (off %d)' % (sess_id_len, off)
        #print tls.encode('hex')

        # Cipher suites
        cs_len = aint(tls[off:off+2])
        off += 2
        x = tls[off:off+cs_len]
        cipher_suites = list_u16_to_u8(ungrease([aint(x[2*i:2*i+2]) for i in xrange(len(x)/2)]))
        off += cs_len

        # Compression
        comp_len = aint(tls[off])
        off += 1
        comp_methods = [aint(x) for x in tls[off:off+comp_len]]
        off += comp_len

        # Extensions
        ext_len = aint(tls[off:off+2])
        off += 2

        sni_host = ''
        curves = []
        pt_fmts = []
        sig_algs = []
        alpn = []
        exts = []
        end = off + ext_len
        while off < end:
            ext_type = aint(tls[off:off+2])
            off += 2
            ext_len = aint(tls[off:off+2])
            off += 2
            exts.append(ext_type)

            if ext_type == 0x0000:
                # SNI
                sni_len = aint(tls[off:off+2])
                sni_type = aint(tls[off+2])
                sni_len2 = aint(tls[off+3:off+5])
                sni_host = tls[off+5:off+5+sni_len2]

            elif ext_type == 0x000a:
                # Elliptic curves
                # len...

                x = tls[off:off+ext_len]
                curves = list_u16_to_u8(ungrease([aint(x[2*i:2*i+2]) for i in xrange(len(x)/2)]))
            elif ext_type == 0x000b:
                # ec_point_fmt
                pt_fmt_len = aint(tls[off])
                pt_fmts = [aint(x) for x in tls[off:off+ext_len]]
            elif ext_type == 0x000d:
                # sig algs
                # Actually a length field, and actually these are 2-byte pairs but
                # this currently matches format...
                sig_algs = [aint(x) for x in tls[off:off+ext_len]]
            elif ext_type == 0x0010:
                # alpn
                # also has a length field...
                alpn = [aint(x) for x in tls[off:off+ext_len]]

            off += ext_len

        exts = list_u16_to_u8(ungrease(exts))


        #print '%s: cs: %s comp: %s exts: %s curves: %s pt_fmts: %s' % \
        #    (sni_host, cipher_suites, comp_methods, exts, curves, pt_fmts)

        add_fingerprint(name, tls_version, chello_version, cipher_suites, comp_methods, exts, curves, pt_fmts, sig_algs, alpn)



for root, dirs, files in os.walk(sys.argv[1]):
    for fname in files:
        if fname.endswith('.pcap'):
            name = fname[:-len('.pcap')]

            if name.endswith('handshake'):
                name = name[:-len('handshake')]
            if name.endswith('.hello'):
                name = name[:-len('.hello')]
            if name.endswith('.header'):
                name = name[:-len('.header')]
            if name == 'hello' or name == 'handshake1' or name == 'handshake2' or name == 'handshake3' or name=='handshake4':
                name = ''
            if name == 'ie' and 'fortigate' in root:
                name = 'fortigate/ie'

            if name == '':
                name = root.split('/')[-1]
            if name.startswith('computer-'):
                name = name[len('computer-'):]


            #print '%s/%s:.....%s' % (root, fname, name)

            fullname = '%s/%s' % (root, fname)
            try:
                parse_pcap(name, fullname)
            except Exception as e:
                print 'Error in %s, parsing "%s": %s' % (name, fullname, e)




print 'fprints = {'
for f in fprints.keys():
    clients = fprints[f]
    print "%s: %s," % (f, clients)
    #print "'%s': %s," % (f, collapse(clients))
    #print "'%s': %s => %s," % (f, clients, collapse(clients))
print '}'

#print fprints
