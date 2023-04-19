from tlsutil import *

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
    return [ord(bya[2*a])*256 + ord(bya[2*a+1]) for a in xrange(len(bya)/2)]

def bytea_to_u8s(bya):
    return [ord(a) for a in bya]

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

# Lookup qTLSFingerprint, QUIC, and TP
def lookup_fingerprint(fid):
    db = get_db()
    # TODO make this a left join on all 3 tables...
    db.cur.execute('''SELECT q.*, t.*, tp.* 
        FROM fps f
        LEFT JOIN quic_fingerprints q
        ON f.qid = q.id
        LEFT JOIN tls_fingerprints_norm_ext t
        ON f.tlsid = t.id
        LEFT JOIN transport_params tp
        ON f.tpid = tp.id
        WHERE f.id=%s''', [int(fid)])
    rows = db.cur.fetchall()
    if len(rows) == 0:
        return None

    #fid_hex = struct.pack('!q', int(fid)).encode('hex')


    # TODO break out qTLSFingerprint(), QUICFingerprint, and TransportParamsFingerprint
    qid, quic_version, client_cid_len, server_cid_len, pkt_num, frames, token_len, \
    tlsid, ch_ver, cipher_suites, comp_methods, exts, curves, pt_fmt, sig_algs, alpn, \
    key_share, psk_kex_modes, supported_versions, cert_comp_algs, record_size_limit, \
    tpid, max_idle_timeout, max_udp_payload_size, initial_max_data, initial_max_stream_data_bidi_local, initial_max_stream_data_bidi_remote, initial_max_stream_data_uni, initial_max_streams_bidi, initial_max_streams_uni, ack_delay_exponent, max_ack_delay, disable_active_migration, active_connection_id_limit = rows[0]

    tls = qTLSFingerprint(tlsid, ch_ver, cipher_suites, comp_methods, exts, curves, \
            pt_fmt, sig_algs, alpn,\
            key_share, psk_kex_modes, supported_versions, cert_comp_algs, record_size_limit)
    quic = QUICFingerprint(qid, quic_version, client_cid_len, server_cid_len, pkt_num, frames, token_len)
    tp = TransportParamsFingerprint(tpid, max_idle_timeout, max_udp_payload_size, initial_max_data, initial_max_stream_data_bidi_local, initial_max_stream_data_bidi_remote, initial_max_stream_data_uni, initial_max_streams_bidi, initial_max_streams_uni, ack_delay_exponent, max_ack_delay, disable_active_migration, active_connection_id_limit)

    return (quic, tls, tp)


class qTLSFingerprint(object):
    def __init__(self, nid, ch_version, cipher_suites, comp_methods, extensions,\
                curves, pt_fmts, sig_algs, alpn,\
                key_share, psk_key_exchange_modes, supported_versions, cert_compression_algs,\
                record_size_limit):
        self.nid = int(nid)
        self.ch_version = ch_version
        self.cipher_suites = cipher_suites
        self.comp_methods = comp_methods
        self.extensions = extensions

        # 2-byte length, followed by list of 2-byte Named Groups
        self.curves = curves

        # 1-byte length, followed by list of 1-byte EC Point Formats
        self.pt_fmts = pt_fmts

        # 2-byte length, followed by list of 2-byte signature algorithms
        self.sig_algs = sig_algs

        # https://tools.ietf.org/html/rfc7301
        # 2-byte total length
        #   1-byte length, alpn
        #   1-byte length, alpn
        #   ...
        self.alpn = alpn

        # https://tools.ietf.org/html/draft-ietf-tls-tls13-28#section-4.2.8
        # List of just pairs of 2-byte named group / 2-byte key length
        # (key omitted)
        self.key_share = key_share

        # https://tools.ietf.org/html/draft-ietf-tls-tls13-28#section-4.2.9
        # List of 1-byte PskKeyExchangeModes (no length)
        self.psk_key_exchange_modes = psk_key_exchange_modes

        # https://tools.ietf.org/html/draft-ietf-tls-tls13-28#section-4.2.1
        # List of 2-byte versions (no length)
        self.supported_versions = supported_versions

        # https://tools.ietf.org/html/draft-ietf-tls-certificate-compression-04
        # 1-byte length, followed by list of 2-byte compression methods
        self.cert_compression_algs = cert_compression_algs

        # https://tools.ietf.org/html/draft-ietf-tls-record-limit-03
        # Single 2-byte record limit
        self.record_size_limit = record_size_limit

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
        cca_len, = struct.unpack('!B', self.cert_compression_algs[0])
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
        pt_len, = struct.unpack('!B', self.pt_fmts[0])
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


class TransportParamsFingerprint(object):
    def __init__(self, nid, max_idle_timeout, max_udp_payload_size, initial_max_data, initial_max_stream_data_bidi_local, initial_max_stream_data_bidi_remote, initial_max_stream_data_uni, initial_max_streams_bidi, initial_max_streams_uni, ack_delay_exponent, max_ack_delay, disable_active_migration, active_connection_id_limit):
        self.nid = nid
        self.max_udp_payload_size = max_udp_payload_size
        self.initial_max_data = initial_max_data
        self.initial_max_stream_data_bidi_local = initial_max_stream_data_bidi_local
        self.initial_max_stream_data_bidi_remote = initial_max_stream_data_bidi_remote
        self.initial_max_stream_data_uni = initial_max_stream_data_uni
        self.initial_max_streams_bidi = initial_max_streams_bidi
        self.initial_max_streams_uni = initial_max_streams_uni
        self.ack_delay_exponent = ack_delay_exponent
        self.max_ack_delay = max_ack_delay
        self.disable_active_migration = disable_active_migration
        self.active_connection_id_limit = active_connection_id_limit
    # TODO: gettrs
