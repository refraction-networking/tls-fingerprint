from tlsutil import *
from qutil import *

def tls_ver_to_str(ver):
    d = {0x0200:    'SSL 2.0',
    0x0300: 'SSL 3.0',
    0x0301: 'TLS 1.0',
    0x0302: 'TLS 1.1',
    0x0303: 'TLS 1.2',
    0x0304: 'TLS 1.3'
    }
    if ver in d:
        return d[ver]
    return '?'

def bytea_to_u16s(bya):
    if bya is None:
        return []
    return [bya[2*a]*256 + bya[2*a+1] for a in range(len(bya)//2)]

def bytea_to_u8s(bya):
    return bya
    #return [ord(a) for a in bya]

def bytea_to_u16_strings(bya, lookup_dict):
    out = []  # dicts of {'n':u16, 's':str}
    for u16 in bytea_to_u16s(bya):
        name = ''
        if u16 in lookup_dict:
            name = lookup_dict[u16]
        name += ' (0x%04x)' % (u16)
        out.append({'n':u16, 's':name})
    return out

def bytea_to_u8_strings(bya, lookup_dict):
    out = [] # dicts of {'n':u8, 's':str}
    for u8 in bytea_to_u8s(bya):
        name = ''
        if u8 in lookup_dict:
            name = lookup_dict[u8]
        name += ' (0x%02x)' % (u8)
        out.append({'n':u8, 's':name})
    return out

def lookup_qfp(db, qid):

    db.cur.execute('SELECT * FROM quic_fingerprints WHERE id=%s', [int(qid)])
    rows = db.cur.fetchall()
    if len(rows) == 0:
        return None

    qid, quic_version, client_cid_len, server_cid_len, pkt_num, frames, token_len = rows[0]
    return QUICFingerprint(qid, quic_version, client_cid_len, server_cid_len, pkt_num, frames, token_len)

def lookup_tls(db, tid):
    db.cur.execute('SELECT * FROM tls_fingerprints_norm_ext WHERE id=%s', [int(tid)])
    rows = db.cur.fetchall()
    if len(rows) == 0:
        return None

    tlsid, ch_ver, cipher_suites, comp_methods, exts, curves, pt_fmt, sig_algs, alpn, \
    key_share, psk_kex_modes, supported_versions, cert_comp_algs, record_size_limit = rows[0]

    return qTLSFingerprint(tlsid, ch_ver, cipher_suites, comp_methods, exts, curves, \
            pt_fmt, sig_algs, alpn,\
            key_share, psk_kex_modes, supported_versions, cert_comp_algs, record_size_limit)

def lookup_qtp(db, qtpid):
    db.cur.execute('SELECT * FROM qtp_fingerprints WHERE id=%s', [int(qtpid)])
    rows = db.cur.fetchall()
    if len(rows) == 0:
        return None

    _, max_idle_timeout, max_udp_payload_size, initial_max_data, initial_max_stream_data_bidi_local, initial_max_stream_data_bidi_remote, initial_max_stream_data_uni, initial_max_streams_bidi, initial_max_streams_uni, ack_delay_exponent, max_ack_delay, active_connection_id_limit, param_ids = rows[0]
    disable_active_migration = None
    return TransportParamsFingerprint(qtpid, param_ids, max_idle_timeout, max_udp_payload_size, initial_max_data, initial_max_stream_data_bidi_local, initial_max_stream_data_bidi_remote, initial_max_stream_data_uni, initial_max_streams_bidi, initial_max_streams_uni, ack_delay_exponent, max_ack_delay, disable_active_migration, active_connection_id_limit)


# Lookup qTLSFingerprint, QUIC, and TP
def lookup_fingerprints(db, fid):
    # TODO make this a left join on all 3 tables...
    db.cur.execute('''SELECT q.*, t.*, qtp.* 
        FROM super_fingerprints f
        LEFT JOIN quic_fingerprints q
        ON f.quic_fp = q.id
        LEFT JOIN tls_fingerprints_norm_ext t
        ON f.tls_fp = t.id
        LEFT JOIN qtp_fingerprints qtp
        ON f.qtp_fp = qtp.id
        WHERE f.id=%s''', [int(fid)])
    rows = db.cur.fetchall()
    if len(rows) == 0:
        return None

    #fid_hex = struct.pack('!q', int(fid)).encode('hex')


    # TODO break out qTLSFingerprint(), QUICFingerprint, and TransportParamsFingerprint
    qid, quic_version, client_cid_len, server_cid_len, pkt_num, frames, token_len, \
    tlsid, ch_ver, cipher_suites, comp_methods, exts, curves, pt_fmt, sig_algs, alpn, \
    key_share, psk_kex_modes, supported_versions, cert_comp_algs, record_size_limit, \
    tpid, max_idle_timeout, max_udp_payload_size, initial_max_data, initial_max_stream_data_bidi_local, initial_max_stream_data_bidi_remote, initial_max_stream_data_uni, initial_max_streams_bidi, initial_max_streams_uni, ack_delay_exponent, max_ack_delay, \
    active_connection_id_limit, qtp_ids = rows[0]
    #disable_active_migration, 

    disable_active_migration = None     # TODO: do we want this?

    tls = qTLSFingerprint(tlsid, ch_ver, cipher_suites, comp_methods, exts, curves, \
            pt_fmt, sig_algs, alpn,\
            key_share, psk_kex_modes, supported_versions, cert_comp_algs, record_size_limit)
    quic = QUICFingerprint(qid, quic_version, client_cid_len, server_cid_len, pkt_num, frames, token_len)
    tp = TransportParamsFingerprint(tpid, qtp_ids, max_idle_timeout, max_udp_payload_size, initial_max_data, initial_max_stream_data_bidi_local, initial_max_stream_data_bidi_remote, initial_max_stream_data_uni, initial_max_streams_bidi, initial_max_streams_uni, ack_delay_exponent, max_ack_delay, disable_active_migration, active_connection_id_limit)

    return SuperFingerprint(fid, quic, tls, tp)

# The list of alpns (these are a list of strings: ["h2", "http/1.1", ...])
def parse_alpns(alpn_str):
    alpns = []
    if alpn_str is not None and len(alpn_str) > 2:
        l, = struct.unpack('!H', alpn_str[0:2])
        idx = 2
        while idx < l:
            n = alpn_str[idx]
            idx += 1
            alpns.append(repr(alpn_str[idx:idx+n])[2:-1])
            idx += n
    return alpns



class SuperFingerprint(object):
    def __init__(self, nid, quic, tls, qtp):
        self.nid = nid
        self.quic = quic
        self.tls = tls
        self.qtp = qtp

    def get_rank(self, db):

        #db.cur.execute('''SELECT id, n, r FROM
        #    (SELECT id, SUM(count) as n, RANK() OVER(ORDER BY SUM(count) DESC) as r, MAX(t) FROM
        #    (SELECT id, count, TIMESTAMP WITH TIME ZONE 'epoch' + unixtime * INTERVAL '1 second' as t FROM measurements) as ts
        #    where age(now(), t) > '2 hour' group by id order by n desc) as j where id=%s''', [int(self.nid)])
        db.cur.execute('select min(case when id=%s then rank end), sum(case when id=%s then seen end), sum(seen) from (select id, sum(count) as seen, rank() over(order by sum(count) desc) as rank from super_measurements group by id) as a;', [int(self.nid), int(self.nid)])

        rank, seen, total = db.cur.fetchall()[0]

        frac_seen = 0.0
        if seen is not None and seen > 0:
            frac_seen = float(seen) / float(total)

        return (rank, seen, frac_seen, total) # self.rank_week, self.seen_week, self.frac_seen_week)






class qTLSFingerprint(object):
    def __init__(self, nid, ch_version, cipher_suites, comp_methods, extensions,\
                curves, pt_fmts, sig_algs, alpn,\
                key_share, psk_key_exchange_modes, supported_versions, cert_compression_algs,\
                record_size_limit):
        self.nid = int(nid)
        self.ch_version = ch_version
        self.cipher_suites = bytes(cipher_suites)
        self.comp_methods = bytes(comp_methods)
        self.extensions = bytes(extensions)

        # 2-byte length, followed by list of 2-byte Named Groups
        self.curves = bytes(curves)

        # 1-byte length, followed by list of 1-byte EC Point Formats
        self.pt_fmts = bytes(pt_fmts)

        # 2-byte length, followed by list of 2-byte signature algorithms
        self.sig_algs = bytes(sig_algs)

        # https://tools.ietf.org/html/rfc7301
        # 2-byte total length
        #   1-byte length, alpn
        #   1-byte length, alpn
        #   ...
        self.alpn = bytes(alpn)

        # https://tools.ietf.org/html/draft-ietf-tls-tls13-28#section-4.2.8
        # List of just pairs of 2-byte named group / 2-byte key length
        # (key omitted)
        self.key_share = bytes(key_share)

        # https://tools.ietf.org/html/draft-ietf-tls-tls13-28#section-4.2.9
        # List of 1-byte PskKeyExchangeModes (no length)
        self.psk_key_exchange_modes = bytes(psk_key_exchange_modes)

        # https://tools.ietf.org/html/draft-ietf-tls-tls13-28#section-4.2.1
        # List of 2-byte versions (no length)
        self.supported_versions = bytes(supported_versions)

        # https://tools.ietf.org/html/draft-ietf-tls-certificate-compression-04
        # 1-byte length, followed by list of 2-byte compression methods
        self.cert_compression_algs = bytes(cert_compression_algs)

        # https://tools.ietf.org/html/draft-ietf-tls-record-limit-03
        # Single 2-byte record limit
        self.record_size_limit = bytes(record_size_limit)

    # String version of client hello version
    def get_ch_version(self):
        return tls_ver_to_str(self.ch_version)

    # returns a list of object strings:
    # [{'s':"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (0xc030)", 'n':0xc030}, ... ]
    def get_ciphers(self):
        return bytea_to_u16_strings(self.cipher_suites, cipher_dict)

    # returns a single string of the concatenated cipher suites, e.g. 'c030c029000a'
    def get_hex_cipher_suite_str(self):
        return ''.join(['%04x' % x for x in bytea_to_u16s(self.cipher_suites)])

    def get_hex_extensions_str(self):
        return ''.join(['%04x' % x for x in bytea_to_u16s(self.extensions)])

    # Note: this includes the length (so you can exact match on =...)
    def get_hex_curves_str(self):
        return ''.join(['%04x' % x for x in bytea_to_u16s(self.curves)])

    def get_hex_supported_versions_str(self):
        return ''.join(['%04x' % x for x in bytea_to_u16s(self.supported_versions)])

    def get_hex_sigalgs_str(self):
        return ''.join(['%04x' % x for x in bytea_to_u16s(self.sig_algs)])

    # returns a list of object strings 
    # [{'s':"server_name (0x0000)", 'n':0x0000}, {'s':"supported_groups (0x000a)", 'n':0x000a}, ... ]
    def get_extensions(self):
        return bytea_to_u16_strings(self.extensions, ext_dict)

    # returns a list of object strings
    # [{'s':"sect233k1 (0x0006)", 'n':0x0006}, ...]
    def get_curves(self):
        if len(self.curves) == 0:
            return []
        curve_len, = struct.unpack('!H', self.curves[0:2])
        if len(self.curves[2:]) != curve_len:
            return [{'s': 'Error (%s)'%self.curves.encode('hex'), 'n':0xffff}]
        return bytea_to_u16_strings(self.curves[2:], curve_dict)

    # returns a list of {'key_len': 16, 'n': 0x001d, 's': 'x25519'}
    def get_key_share(self):
        # List of pairs of 2-byte named group / 2-byte key length
        out = []  # dicts of {'n':u16, 's':str}
        u16 = bytea_to_u16s(self.key_share)
        for group, key_len in zip(u16[::2], u16[1::2]):
            name = ''
            if group in curve_dict:
                name = curve_dict[group]
            name += ' (0x%04x)' % group
            out.append({'key_len': key_len,
                        'n': group,
                        's': name})
        return out

    def get_psk_key_exchange_modes(self):
        return bytea_to_u8_strings(self.psk_key_exchange_modes, psk_key_exchange_modes_dict)

    def get_supported_versions(self):
        return bytea_to_u16_strings(self.supported_versions, versions_dict)

    def get_cert_compression_algs(self):
        if len(self.cert_compression_algs) == 0:
            return []
        cca_len = self.cert_compression_algs[0]
        if len(self.cert_compression_algs[1:]) != cca_len:
            return [{'s': 'Error (%s)'%self.cert_compression_algs.encode('hex'), 'n':0x0000}]
        return bytea_to_u16_strings(self.cert_compression_algs[1:], cert_compression_algs_dict)

    def get_record_size_limit(self):
        x = bytea_to_u16s(self.record_size_limit)
        if len(x) == 0:
            return None
        return x[0]

    def get_pt_fmts(self):
        if len(self.pt_fmts) == 0:
            return []
        pt_len = self.pt_fmts[0]
        if len(self.pt_fmts[1:]) != pt_len:
            return [{'s': 'Error (%s)'%self.pt_fmts.encode('hex'), 'n':0xff}]
        return bytea_to_u8_strings(self.pt_fmts[1:], pt_fmt_dict)

    # returns list of object strings;
    # usually just [{'s':"null (0x00)", 'n':0x00}]
    def get_comp_methods(self):
        comps = []
        for comp in bytea_to_u8s(self.comp_methods):
            comp_obj = {}
            if comp == 0:   comp_obj['s'] = 'null'
            elif comp == 1: comp_obj['s'] = 'DEFLATE'
            elif comp == 64: comp_obj['s'] = 'LZS'
            else: comp_obj['s'] = 'UNKNOWN'
            comp_obj['s'] += ' (0x%02x)' % (comp)
            comp_obj['n'] = comp
            comps.append(comp_obj)
        return comps

    def get_alpns(self):
        return parse_alpns(self.alpn)

    def get_sig_algs(self):
        return sig_algs_to_str(self.sig_algs)

    #def get_useragents(self):
    #    #from prod import db
    #    db = get_db()
    #    #db.conn.rollback()
    #    db.cur.execute("SELECT count(*) as d, useragent from useragents where id=%s group by useragent order by d desc", [int(self.nid)])
    #    rows = db.cur.fetchall()
    #    useragents = []

    #    if len(rows) > 0:
    #        useragents = [row[1] for row in rows]
    #    else:
    #        # check normalized form
    #        db.cur.execute('''SELECT * FROM fingerprint_map WHERE id=%s''', [int(self.nid)])
    #        rows = db.cur.fetchall()
    #        if len(rows) > 0:
    #            norm_id = rows[0][1] # norm_ext_id
    #            db.cur.execute("SELECT count(*) as d, useragent from useragents where id=%s group by useragent order by d desc", [int(norm_id)])
    #            rows = db.cur.fetchall()
    #            if len(rows) > 0:
    #                useragents = [row[1] for row in rows]

    #    return useragents

    #def get_norm_id(self):
    #    db = get_db()
    #    nid = int(self.nid)
    #    db.cur.execute('''SELECT * FROM fingerprint_map WHERE id=%s''', [nid])
    #    rows = db.cur.fetchall()
    #    if len(rows) > 0:
    #        return int(rows[0][1])
    #    return nid # assuming self.nid is always "good"

    def get_rank(self):
        nid = self.get_norm_id()
        db = get_db()

        #db.cur.execute('''SELECT id, n, r FROM
        #    (SELECT id, SUM(count) as n, RANK() OVER(ORDER BY SUM(count) DESC) as r, MAX(t) FROM
        #    (SELECT id, count, TIMESTAMP WITH TIME ZONE 'epoch' + unixtime * INTERVAL '1 second' as t FROM measurements) as ts
        #    where age(now(), t) > '2 hour' group by id order by n desc) as j where id=%s''', [int(self.nid)])
        db.cur.execute('''SELECT * FROM mv_ranked_fingerprints_norm_ext where id=%s''', [nid])
        rows = db.cur.fetchall()
        self.seen = 0
        self.rank = -1
        self.frac_seen = 0.0

        if len(rows) > 0:
            self.seen = rows[0][1]
            self.rank = rows[0][2]

        db.cur.execute('''SELECT * FROM mv_ranked_fingerprints_norm_ext_week where id=%s''', [nid])

        rows = db.cur.fetchall()
        self.seen_week = 0
        self.rank_week = -1
        self.frac_seen_week = 0.0
        if len(rows) > 0:
            self.seen_week = rows[0][1]
            self.rank_week = rows[0][2]

        #db.cur.execute("""select sum(count) from
        #    (select id, count, timestamp with time zone 'epoch' + unixtime * INTERVAL '1 second' as t from measurements) as ts
        #    where age(now(), t) > '2 hour'""")
        total = get_total_seen()
        total_week = get_total_seen_week()

        self.frac_seen = float(self.seen) / int(total)
        self.frac_seen_week = float(self.seen_week) / int(total_week)

        return (self.rank, self.seen, self.frac_seen, self.rank_week, self.seen_week, self.frac_seen_week)






class QUICFingerprint(object):
    def __init__(self, nid, version, sid_len, did_len, pkt_num, frames, token_len):
        self.nid = nid
        self.version = version
        self.sid_len = sid_len
        self.did_len = did_len
        self.frames = frames
        self.token_len = token_len
        self.pkt_num = pkt_num
    # TODO: string getters

    def get_version(self):
        return self.version.hex()
    def get_pkt_num(self):
        return self.pkt_num.hex()
    def get_frames_str(self):
        out = []
        for fid in self.frames:
            fid = int.from_bytes(fid, byteorder='big')
            fs = 'UNKNOWN'
            if fid in quic_frame_types:
                fs = quic_frame_types[fid]
            name = '%s (0x%02x)' % (fs, fid)
            out.append({'n':fid, 's':name})
        return out

class Varint(object):
    def __init__(self, b=b''):
        self.b = bytes(b)

    # Used to be this, but we zeroed out the length field
    def __decode_varint__(self):
        if len(self.b) == 0:
            return 0
        # Get 2 most significant bits
        msb = self.b[0] >> 6
        blen = 1 << msb

        # Mask off length bits
        n = self.b[0] & 0x3f
        for i in range(1, blen):
            n = (n << 8) + self.b[i]
        return n

    def __int__(self):
        return int.from_bytes(self.b, 'big')

    def __str__(self):
        if len(self.b) == 0:
            return ''
        return '%d (%s)' % (int(self), self.b.hex())


class TransportParamsFingerprint(object):
    def __init__(self, nid, param_ids, max_idle_timeout, max_udp_payload_size, initial_max_data, initial_max_stream_data_bidi_local, initial_max_stream_data_bidi_remote, initial_max_stream_data_uni, initial_max_streams_bidi, initial_max_streams_uni, ack_delay_exponent, max_ack_delay, disable_active_migration, active_connection_id_limit):
        self.nid = nid
        self.param_ids = param_ids
        self.max_idle_timeout = Varint(max_idle_timeout)
        self.max_udp_payload_size = Varint(max_udp_payload_size)
        self.initial_max_data = Varint(initial_max_data)
        self.initial_max_stream_data_bidi_local = Varint(initial_max_stream_data_bidi_local)
        self.initial_max_stream_data_bidi_remote = Varint(initial_max_stream_data_bidi_remote)
        self.initial_max_stream_data_uni = Varint(initial_max_stream_data_uni)
        self.initial_max_streams_bidi = Varint(initial_max_streams_bidi)
        self.initial_max_streams_uni = Varint(initial_max_streams_uni)
        self.ack_delay_exponent = Varint(ack_delay_exponent)
        self.max_ack_delay = Varint(max_ack_delay)
        #self.disable_active_migration = Varint(disable_active_migration)
        self.active_connection_id_limit = Varint(active_connection_id_limit)
    # TODO: gettrs

    def get_param_ids(self):
        out = []
        for pid in self.param_ids:
            ps = 'UNKNOWN'
            if pid in quic_transport_param_types:
                ps = quic_transport_param_types[pid]
            name = '%s (%d)' % (ps, pid)
            out.append({'n':pid, 's':name})
        return out
