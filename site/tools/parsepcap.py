#!/usr/bin/python

import argparse
import pcap
import dpkt
import binascii
import hashlib
import struct
import sys
#import traceback

PRINT_SQL = False


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

# convert lists of u16 to list of u8s
def list_u16_to_u8(l):
    return [u8 for pair in [[u16 >> 8, u16 & 0xff] for u16 in l] for u8 in pair]

def list_u8_to_u16(l):
    return [u16 for u16 in [l[i] << 8 | l[i + 1] for i in range(0, len(l), 2)]]

fprints = {}

#convenience function for generating fingerprint
def update_arr(h, arr):
    h.update(struct.pack('>L', len(arr)))
    h.update(''.join([chr(a) for a in arr]))

class Fingerprint:
    def __init__(self, tls_version, ch_version, cipher_suites, comp_methods, extensions,
                 elliptic_curves, ec_point_fmt, sig_algs, alpn,
                 key_share, psk_key_exchange_modes, supported_versions, cert_compression_algs, record_size_limit,
                 sni=""):
        self.tls_version = tls_version
        self.ch_version = ch_version
        self.cipher_suites = cipher_suites
        self.comp_methods = comp_methods
        self.extensions = extensions
        self.extensions_norm = self.norm_ext(extensions)
        self.elliptic_curves = elliptic_curves
        self.ec_point_fmt = ec_point_fmt
        self.sig_algs = sig_algs
        self.alpn = alpn
        self.key_share = key_share
        self.psk_key_exchange_modes = psk_key_exchange_modes
        self.supported_versions = supported_versions
        self.cert_compression_algs = cert_compression_algs
        self.record_size_limit = record_size_limit
        self.id = None
        self.sni = sni

    def print_sql(self):
        print("  INSERT INTO fingerprints (id, record_tls_version, ch_tls_version, cipher_suites,\
                    compression_methods, extensions, named_groups, ec_point_fmt, sig_algs, alpn,\
                    key_share, psk_key_exchange_modes, supported_versions, cert_compression_algs,\
                    record_size_limit) VALUES (%d, %d, %d, '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s');" % \
              (self.id, self.tls_version, self.ch_version, dbs(self.cipher_suites), dbs(self.comp_methods),
               dbs(self.extensions),
               dbs(self.elliptic_curves), dbs(self.ec_point_fmt), dbs(self.sig_algs), dbs(self.alpn),
               dbs(self.key_share), dbs(self.psk_key_exchange_modes), dbs(self.supported_versions), dbs(self.cert_compression_algs),
               dbs(self.record_size_limit)))

    def norm_ext(exts):
        exts_u16 = list_u8_to_u16(exts)
        exts_u16.sort()
        return list_u16_to_u8(exts_u16)

    @staticmethod
    def from_tls_data(tls):
        if len(tls) == 0:
            return None
        if tls[0] != '\x16':
            # Not a handshake
            return None
        tls_version = aint(tls[1:3])
        tls_len = aint(tls[3:5])
        hs_type = tls[5]
        if hs_type != '\x01':
            # not a client hello
            return None

        # Parse client hello
        chello_len = aint(tls[6:9])
        chello_version = aint(tls[9:11])
        rand = tls[11:11 + 32]
        off = 11 + 32

        # session ID
        sess_id_len = aint(tls[off])
        off += 1 + sess_id_len

        # print 'sess_id len %d (off %d)' % (sess_id_len, off)
        # print tls.encode('hex')

        # Cipher suites
        cs_len = aint(tls[off:off + 2])
        off += 2
        x = tls[off:off + cs_len]
        cipher_suites = list_u16_to_u8(ungrease([aint(x[2 * i:2 * i + 2]) for i in range(len(x) / 2)]))
        off += cs_len

        # Compression
        comp_len = aint(tls[off])
        off += 1
        comp_methods = [aint(x) for x in tls[off:off + comp_len]]
        off += comp_len

        # Extensions
        ext_len = aint(tls[off:off + 2])
        off += 2

        sni_host = ''
        curves = []
        pt_fmts = []
        sig_algs = []
        alpn = []
        key_share = []
        psk_key_exchange_modes = []
        supported_versions = []
        cert_comp_algs = []
        record_size_limit = []
        exts = []
        end = off + ext_len
        while off < end:
            ext_type = aint(tls[off:off + 2])
            off += 2
            ext_len = aint(tls[off:off + 2])
            off += 2
            exts.append(ext_type)

            if ext_type == 0x0000:
                # SNI
                sni_len = aint(tls[off:off + 2])
                sni_type = aint(tls[off + 2])
                sni_len2 = aint(tls[off + 3:off + 5])
                sni_host = tls[off + 5:off + 5 + sni_len2]

            elif ext_type == 0x000a:
                # Elliptic curves
                # len...

                x = tls[off:off + ext_len]
                curves = list_u16_to_u8(ungrease([aint(x[2 * i:2 * i + 2]) for i in range(len(x) / 2)]))
            elif ext_type == 0x000b:
                # ec_point_fmt
                pt_fmt_len = aint(tls[off])
                pt_fmts = [aint(x) for x in tls[off:off + ext_len]]
            elif ext_type == 0x000d:
                # sig algs
                # Actually a length field, and actually these are 2-byte pairs but
                # this currently matches format...
                sig_algs = [aint(x) for x in tls[off:off + ext_len]]
            elif ext_type == 0x0010:
                # alpn
                # also has a length field...
                alpn = [aint(x) for x in tls[off:off + ext_len]]
            elif ext_type == 0x0033:
                # key share
                this_ext = tls[off:off+ext_len]
                overall_len = aint(this_ext[0:2])
                groups = []
                idx = 2
                while idx+2 < len(this_ext):
                    # parse the named group
                    group = ungrease_one(aint(this_ext[idx:idx+2]))
                    # skip the next bytes
                    key_len = aint(this_ext[idx+2:idx+4])
                    groups.append(group)
                    groups.append(key_len)
                    idx += 2 + 2 + key_len

                key_share = list_u16_to_u8(groups)
            elif ext_type == 0x002d:
                # psk_key_exchange_modes
                # skip length
                psk_key_exchange_modes = [aint(x) for x in tls[off+1:off+ext_len]]
            elif ext_type == 0x002b:
                # supported_versions
                x = tls[off+1:off+ext_len]   # skip length
                supported_versions = list_u16_to_u8(ungrease([aint(x[2*i:2*i+2]) for i in range(len(x)/2)]))
            elif ext_type == 0x001b:
                # compressed_cert
                cert_comp_algs = [aint(x) for x in tls[off:off+ext_len]]
            elif ext_type == 0x001c:
                record_size_limit = [aint(x) for x in tls[off:off+ext_len]]

 

            off += ext_len

        exts = list_u16_to_u8(ungrease(exts))
        return Fingerprint(tls_version, chello_version, cipher_suites, comp_methods,
                                         exts, curves, pt_fmts, sig_algs, alpn,
                                         key_share, psk_key_exchange_modes, supported_versions,
                                         cert_comp_algs, record_size_limit, sni=sni_host)
        #return Fingerprint(tls_version, chello_version, cipher_suites, comp_methods,
        #                   exts, curves, pt_fmts, sig_algs, alpn, id, sni=sni_host)


    def get_fingerprint_v2(self):
        h = hashlib.sha1()
        h.update(struct.pack('>HH', self.tls_version, self.ch_version))

        update_arr(h, self.cipher_suites)
        update_arr(h, self.comp_methods)
        update_arr(h, self.extensions)
        update_arr(h, self.elliptic_curves)
        update_arr(h, self.ec_point_fmt)
        update_arr(h, self.sig_algs)
        update_arr(h, self.alpn)

        update_arr(h, self.key_share)
        update_arr(h, self.psk_key_exchange_modes)
        update_arr(h, self.supported_versions)
        update_arr(h, self.cert_compression_algs)
        update_arr(h, self.record_size_limit)

        out, = struct.unpack('>q', h.digest()[0:8])
        return out

    def get_fingerprint_v1(self):
        h = hashlib.sha1()
        h.update(struct.pack('>HH', self.tls_version, self.ch_version))

        update_arr(h, self.cipher_suites)
        update_arr(h, self.comp_methods)
        update_arr(h, self.extensions)
        update_arr(h, self.elliptic_curves)
        update_arr(h, self.ec_point_fmt)
        update_arr(h, self.sig_algs)
        update_arr(h, self.alpn)

        out, = struct.unpack('>q', h.digest()[0:8])
        return out

    def get_fingerprint(self):
        if self.id is None:
            self.id = self.get_fingerprint_v2()
        return self.id

    def get_fingerprint_norm(self):
        h = hashlib.sha1()
        h.update(struct.pack('>HH', self.tls_version, self.ch_version))

        update_arr(h, self.cipher_suites)
        update_arr(h, self.comp_methods)

        # TODO: check type, content (if len included), etc
        # feed sorted list in
        update_arr(h, self.extensions_norm)

        update_arr(h, self.elliptic_curves)
        update_arr(h, self.ec_point_fmt)
        update_arr(h, self.sig_algs)
        update_arr(h, self.alpn)

        update_arr(h, self.key_share)
        update_arr(h, self.psk_key_exchange_modes)
        update_arr(h, self.supported_versions)
        update_arr(h, self.cert_compression_algs)
        update_arr(h, self.record_size_limit)

        out, = struct.unpack('>q', h.digest()[0:8])
        return out

def dbs(s):
    return '\\x' + ''.join(['%02x' % c for c in s])


def add_fingerprint(fingerprint):
    global fprints
    # r = re.compile('([a-z]+)([0-9]+)\_[0-9]+([a-z0-9]+)')  #fingerprints2
    # r = re.compile('([a-z]+)([0-9]+)\_([a-z0-9]+)')    # fingerprints5
    # matches = r.match(sni_host)
    # if matches is None:
    #    raise Exception('%s has no match' % sni_host)
    # browser = matches.group(1)
    # version = matches.group(2)
    # os = matches.group(3)

    # if os == 'windows7':
    #    os = 'win7'
    # elif os == 'osxsierra':
    #    os = 'osx'

    # f = '(%s, %s, %s, %s, %s, %s, %s, %s, %s)' % (tls_version, ch_version, cipher_suites, comp_methods, exts, curves, pt_fmts, sig_algs, alpn)
    if fingerprint.id not in fprints:
        fprints[fingerprint.id] = []
    # b = '%s_%s_%s' % (browser, version, os)
    print('%s: %s' % (fingerprint.sni_host, fingerprint.id))
    return

    b = sni_host.split('.')[0]
    if b not in fprints[f]:
        fprints[f].append(b)

def parse_pcap(pcap_fname):
    global PRINT_SQL
    n = 0
    ret = []
    p = pcap.pcap(pcap_fname)
    for ts, pkt in p:
        try:
            n += 1
            try:
                ip = None
                eth = dpkt.ethernet.Ethernet(pkt)
                if eth.type != dpkt.ethernet.ETH_TYPE_IP and eth.type != dpkt.ethernet.ETH_TYPE_IP6:
                    if eth.type == dpkt.ethernet.ETH_TYPE_PPPoE:
                        if eth.data.data.p != 0x21:
                            continue
                        eth = eth.data.data
                    else:
                        # try it as a IP packet?
                        ip = dpkt.ip.IP(pkt)
            except dpkt.dpkt.NeedData:
                eth = dpkt.sll.SLL(pkt)
                if eth.ethtype != dpkt.ethernet.ETH_TYPE_IP:
                    continue

            if ip is None:
                ip = eth.data
            if ip.p != dpkt.ip.IP_PROTO_TCP:
                continue
            tcp = ip.data
            #if tcp.dport != 443 and tcp.dport != 8443:
            #    continue

            fingerprint = Fingerprint.from_tls_data(tcp.data)
            if fingerprint is not None:
                ret.append((n, fingerprint.sni, fingerprint.get_fingerprint()))
                if PRINT_SQL:
                    fingerprint.print_sql()

        except Exception as e:
            print('Error in pkt %d: %s' % (n, e))
            #print traceback.print_exc(file=sys.stdout)

    return ret


def parse_hex(hexfile_name):
    with open(hexfile_name) as f:
        hex_str = f.read()
        bin_str = binascii.unhexlify(hex_str)
        fingerprint = Fingerprint.from_tls_data(bin_str)
        print('%s: %d' % (fingerprint.sni, fingerprint.get_fingerprint()))
        if PRINT_SQL:
            fingerprint.print_sql()


def main():
    parser = argparse.ArgumentParser(description='Parses pcap files')
    parser.add_argument("input_file", help="Name of file to parse.", type=str)
    parser.add_argument('-s', '--sql-query-print', dest='PRINT_SQL', action='store_true',
                        help="Print SQL query to add parsed fingerprints to databse")
    args = parser.parse_args()

    global PRINT_SQL
    PRINT_SQL = args.PRINT_SQL

    fps = parse_pcap(args.input_file)
    uniq = {}
    for pkt_n, sni, fp in fps:
        print('#%d %s: %d' % (pkt_n, sni, fp))
        if fp not in uniq:
            uniq[fp] = 0
        uniq[fp] += 1

    print('----')
    for fp, num in sorted(uniq.items(), key=lambda x: x[1], reverse=True):
        print('%d %s %d'  % (fp, struct.pack('!q', fp).encode('hex'), num))


if __name__ == "__main__":
    main()


# print 'fprints = {'
# for f in fprints.keys():
#    clients = fprints[f]
#    print "%s: %s," % (f, clients)
#    #print "'%s': %s," % (f, collapse(clients))
#    #print "'%s': %s => %s," % (f, clients, collapse(clients))
# print '}'

# print fprints
