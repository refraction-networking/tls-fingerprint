from flask import *
from tlsutil import *
import struct
#from diff import myers_diff
import diff
import time
from werkzeug.utils import secure_filename
from tools import parsepcap, db, api
import os
import pickle
import math

# const
UPLOAD_FOLDER = '/tmp/'
ALLOWED_EXTENSIONS = set(['pcap', 'pcapng'])

# var
application = app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
# db_conn_pool = db.get_pool()
db_conn_pool = db.get_fake_pool() # for testing

def allowed_file(filename):
    return '.' in filename and \
            filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def hid(nid: int):
    # return struct.pack('!q', nid).hex()
    # rewrite for python3
    return struct.pack('!q', nid).hex()

def tls_ver_to_str(ver):
    d = {
        0x0200: 'SSL 2.0',
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
    for u8 in bya:
        name = ''
        if u8 in lookup_dict:
            name = lookup_dict[u8]
        name += ' (0x%02x)' % (u8)
        out.append({'n':u8, 's':name})
    return out

def hex_to_int64(h):
    u = int(h, 16)
    return (u & ((1 << 63) - 1)) - (u & (1 << 63))

#@cache.cached(key_prefix="total_seen13", timeout=3*3600)
def get_total_seen():
    global db_conn_pool
    with db_conn_pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute('''select sum(seen) from mv_ranked_fingerprints''')
            row = cur.fetchone()
            if row is None or row[0] is None:
                return 1
            return int(row[0])

#@cache.cached(key_prefix="total_seen_week13", timeout=3*3600)
def get_total_seen_week():
    global db_conn_pool
    with db_conn_pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute('''select sum(seen) from mv_ranked_fingerprints_week''')
            row = cur.fetchone()
            if row is None or row[0] is None:
                return 1
            return int(row[0])

#@cache.cached(key_prefix="total_fps13", timeout=3*3600)
def get_total_fps():
    global db_conn_pool
    with db_conn_pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute('''select count(*) from mv_ranked_fingerprints''')
            row = cur.fetchone()
            if row is None or row[0] is None:
                return 1
            return int(row[0])

def get_labels_for_fp(nid):
    global db_conn_pool
    with db_conn_pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute('select labels.lid, label from fingerprint_labels left join labels on fingerprint_labels.lid=labels.lid where fid=%s', [nid])
            out = []
            for row in cur.fetchall():
                out.append({'lid': row[0], 'name': row[1]})
            return out

# The list of alpns (these are a list of strings: ["h2", "http/1.1", ...])
def parse_alpns(alpn_str):
    alpns = []
    if alpn_str is not None and len(alpn_str) > 2:
        l, = struct.unpack('!H', alpn_str[0:2])
        idx = 2
        while idx < l:
            # n, = struct.unpack('!B', alpn_str[idx]) #py2
            alpn_len = alpn_str[idx]
            idx += 1

            alpn = alpn_str[idx:idx+alpn_len]
            
            decoded = ''
            try:
                alpns.append(alpn.decode('utf-8'))
            except:
                alpns.append(alpn.hex())

            idx += alpn_len
    return alpns

def get_top_fps():
    global db_conn_pool
    with db_conn_pool.connection() as conn:
        with conn.cursor() as cur:
            # Get total...
            total = get_total_seen_week()

            cur.execute('''select id, min(cluster_rank) as cluster_num, min(seen) as seen, min(rank) as rank
                    from mv_ranked_fingerprints_week left join cluster_edges
                        on mv_ranked_fingerprints_week.id=cluster_edges.source
                    group by id order by seen desc limit 20;''')
            rows = cur.fetchall()
            top_ids = []
            for row in rows:
                nid, cluster, seen, rank = row
                nid = int(nid)
                top_ids.append({'nid': nid,
                                'id': hid(nid),
                                'count': seen,
                                'rank': rank,
                                'frac': 100.0*float(seen) / total,
                                'labels': get_labels_for_fp(nid),
                                'cluster': cluster})
            return top_ids

def get_total_seen_norm_ext_week():
    global db_conn_pool
    with db_conn_pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute('''select sum(seen) from public.mv_ranked_fingerprints_norm_ext_week''')
            row = cur.fetchone()
            if row is None or row[0] is None:
                return 1
            return int(row[0])

def get_top_norm_fps():
    global db_conn_pool
    with db_conn_pool.connection() as conn:
        with conn.cursor() as cur:
            # Get total...
            total = get_total_seen_norm_ext_week()

            #db.cur.execute('''select id, n, r from
            #    (select id, sum(count) as n, rank() over(order by sum(count) desc) as r, max(t) from
            #    (select id, count, timestamp with time zone 'epoch' + unixtime * INTERVAL '1 second' as t from measurements) as i
            #    where age(now(), t) > '2 hour' group by id order by n desc) as j LIMIT 20;''')
            #db.cur.execute('''select id, seen, rank from mv_ranked_fingerprints_week limit 20''')
            cur.execute('''select id, seen, rank from mv_ranked_fingerprints_norm_ext_week 
                            order by seen desc limit 20;''')
            rows = cur.fetchall()
            top_ids = []
            for row in rows:
                nid, seen, rank = row
                nid = int(nid)
                top_ids.append({'nid': nid,
                                'id': hid(nid),
                                'count': seen,
                                'rank': rank,
                                'frac': 100.0*float(seen) / total,
                                'labels': get_labels_for_fp(nid)})
            return top_ids

def levenshtein(s1, s2):
    if len(s1) < len(s2):
        return levenshtein(s2, s1)
    # len(s1) >= len(s2)
    if len(s2) == 0:
        return len(s1)
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1 # j+1 instead of j since previous_row and current_row are one character longer
            deletions = current_row[j] + 1       # than s2
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]

class TLSFingerprint(object):
    def __init__(self, nid: int):
        self.nid = nid
        self.tls_record_version = 0
        self.tls_handshake_version = 0
        self.cipher_suites = None
        self.compression_methods = None
        self.extensions = None
        self.supported_groups = None
        self.ec_point_formats = None
        self.signature_algorithms = None
        self.alpn = None
        self.key_share = None
        self.psk_key_exchange_modes = None
        self.supported_versions = None
        self.compress_certificate = None
        self.record_size_limit = None
    
    # String version of tls version
    def get_tls_record_version(self):
        return tls_ver_to_str(self.tls_record_version)

    def set_tls_record_version(self, tls_record_version):
        self.tls_record_version = tls_record_version
        return self

    # String version of client hello version
    def get_tls_handshake_version(self):
        return tls_ver_to_str(self.tls_handshake_version)

    def set_tls_handshake_version(self, tls_handshake_version):
        self.tls_handshake_version = tls_handshake_version
        return self

    # returns a list of object strings:
    # [{'s':"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (0xc030)", 'n':0xc030}, ... ]
    def get_cipher_suites(self):
        return bytea_to_u16_strings(self.cipher_suites, cipher_dict)
    
    def set_cipher_suites(self, cipher_suites):
        self.cipher_suites = cipher_suites
        return self

    # returns list of object strings;
    # usually just [{'s':"null (0x00)", 'n':0x00}]
    def get_compression_methods(self):
        comps = []
        for comp in self.compression_methods:
            comp_obj = {}
            if comp == 0:   comp_obj['s'] = 'null'
            elif comp == 1: comp_obj['s'] = 'DEFLATE'
            elif comp == 64: comp_obj['s'] = 'LZS'
            else: comp_obj['s'] = 'UNKNOWN'
            comp_obj['s'] += ' (0x%02x)' % (comp)
            comp_obj['n'] = comp
            comps.append(comp_obj)
        return comps
    
    def set_compression_methods(self, compression_methods):
        self.compression_methods = compression_methods
        return self

    # returns a list of object strings 
    # [{'s':"server_name (0x0000)", 'n':0x0000}, {'s':"supported_groups (0x000a)", 'n':0x000a}, ... ]
    def get_extensions(self):
        return bytea_to_u16_strings(self.extensions, ext_dict)

    def set_extensions(self, extensions):
        self.extensions = extensions
        return self

    # returns a list of object strings
    # [{'s':"sect233k1 (0x0006)", 'n':0x0006}, ...]
    def get_supported_groups(self):
        if len(self.supported_groups) == 0:
            return []
        curve_len, = struct.unpack('!H', self.supported_groups[0:2])
        if len(self.supported_groups[2:]) != curve_len:
            return [{'s': 'Error (%s)'%self.supported_groups.hex(), 'n':0xffff}]
        return bytea_to_u16_strings(self.supported_groups[2:], curve_dict)

    def set_supported_groups(self, supported_groups):
        self.supported_groups = supported_groups
        return self
    
    def get_ec_point_formats(self):
        if len(self.ec_point_formats) == 0:
            return []
        pt_len = self.ec_point_formats[0]
        if len(self.ec_point_formats[1:]) != pt_len:
            return [{'s': 'Error (%s)'%self.ec_point_formats.hex(), 'n':0xff}]
        return bytea_to_u8_strings(self.ec_point_formats[1:], pt_fmt_dict)
    
    def set_ec_point_formats(self, ec_point_formats):
        self.ec_point_formats = ec_point_formats
        return self

    def get_signature_algorithms(self):
        return sig_algs_to_str(self.signature_algorithms)
    
    def set_signature_algorithms(self, signature_algorithms):
        self.signature_algorithms = signature_algorithms
        return self

    def get_alpn(self):
        return parse_alpns(self.alpn)

    def set_alpn(self, alpn):
        self.alpn = alpn
        return self

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

    def set_key_share(self, key_share):
        self.key_share = key_share
        return self

    def get_psk_key_exchange_modes(self):
        return bytea_to_u8_strings(self.psk_key_exchange_modes, psk_key_exchange_modes_dict)

    def set_psk_key_exchange_modes(self, psk_key_exchange_modes):
        self.psk_key_exchange_modes = psk_key_exchange_modes
        return self

    def get_supported_versions(self):
        return bytea_to_u16_strings(self.supported_versions, versions_dict)

    def set_supported_versions(self, supported_versions):
        self.supported_versions = supported_versions
        return self

    def get_compress_certificate(self):
        if len(self.compress_certificate) == 0:
            return []
        cca_len = self.compress_certificate[0]
        if len(self.compress_certificate[1:]) != cca_len:
            return [{'s': 'Error (%s)'%self.compress_certificate.hex(), 'n':0x0000}]
        return bytea_to_u16_strings(self.compress_certificate[1:], cert_compression_algs_dict)

    def set_compress_certificate(self, compress_certificate):
        self.compress_certificate = compress_certificate
        return self

    def get_record_size_limit(self):
        x = bytea_to_u16s(self.record_size_limit)
        if len(x) == 0:
            return None
        return x[0]

    def set_record_size_limit(self, record_size_limit):
        self.record_size_limit = record_size_limit
        return self

    def get_useragents(self):
        global db_conn_pool
        with db_conn_pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT count(*) as d, useragent from useragents where id=%s group by useragent order by d desc", [self.nid])
                rows = cur.fetchall()
                useragents = []

                if len(rows) > 0:
                    useragents = [row[1] for row in rows]
                else:
                    # check normalized form
                    cur.execute('''SELECT * FROM fingerprint_map WHERE id=%s''', [int(self.nid)])
                    rows = cur.fetchall()
                    if len(rows) > 0:
                        norm_id = rows[0][1] # norm_ext_id
                        cur.execute("SELECT count(*) as d, useragent from useragents where id=%s group by useragent order by d desc", [int(norm_id)])
                        rows = cur.fetchall()
                        if len(rows) > 0:
                            useragents = [row[1] for row in rows]

                return useragents

    def get_norm_id(self):
        global db_conn_pool
        with db_conn_pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute('''SELECT * FROM fingerprint_map WHERE id=%s''', [self.nid])
                row = cur.fetchone()
                if row is not None:
                    return int(row[1])
                return self.nid # when inquired for norm_id of a norm_id, return itself

    def get_rank(self):
        global db_conn_pool
        with db_conn_pool.connection() as conn:
            with conn.cursor() as cur:
                nid = self.get_norm_id()
                
                cur.execute('''SELECT * FROM mv_ranked_fingerprints_norm_ext where id=%s''', [nid])
                row = cur.fetchone()
                self.seen = 0
                self.rank = -1
                self.frac_seen = 0.0

                if row is not None:
                    self.seen = row[1]
                    self.rank = row[2]

                cur.execute('''SELECT * FROM mv_ranked_fingerprints_norm_ext_week where id=%s''', [nid])

                row = cur.fetchone()
                self.seen_week = 0
                self.rank_week = -1
                self.frac_seen_week = 0.0
                if row is not None:
                    self.seen_week = row[1]
                    self.rank_week = row[2]

                total = get_total_seen()
                total_week = get_total_seen_week()

                self.frac_seen = float(self.seen) / int(total)
                self.frac_seen_week = float(self.seen_week) / int(total_week)

                return (self.rank, self.seen, self.frac_seen, self.rank_week, self.seen_week, self.frac_seen_week)

    def get_lev_dist(self, other):
        return levenshtein(bytea_to_u16s(self.extensions), bytea_to_u16s(other.extensions)) + \
        levenshtein(bytea_to_u16s(self.cipher_suites), bytea_to_u16s(other.cipher_suites)) + \
        levenshtein(bytea_to_u16s(self.supported_groups), bytea_to_u16s(other.supported_groups)) + \
        levenshtein(self.compression_methods, other.compression_methods) + \
        levenshtein(self.get_alpn(), other.get_alpn()) + \
        levenshtein(self.get_signature_algorithms(), other.get_signature_algorithms())

    # get_related was once used for clustering, but now it is used for related fingerprints, re-defined 
    # as: 
    # - For an observed real-world fingerprint, get a few other observed fingerprints normalize to the same one
    # - For a normalized hypothetical fingerprint, get a few observed fingerprints which normalize to it
    def get_related(self, fetch_labels=False):
        with db_conn_pool.connection() as conn:
            with conn.cursor() as cur:
                related = []
                norm_id = self.get_norm_id()        
                ## first check how many in total
                cur.execute('''SELECT count(1) FROM fingerprint_map as map WHERE map.norm_ext_id=%s;''', [norm_id])
                rows = cur.fetchall()
                if len(rows) == 0:
                    return related

                # if more than 16 known fingerprints normalize to this one, show top 10
                if rows[0][0] > 16:
                    cur.execute('''SELECT id FROM fingerprint_map as map WHERE map.norm_ext_id = %s AND id != %s ORDER BY map.count DESC LIMIT 10;''', [norm_id, self.nid])
                else: # show all (no more than 16)
                    cur.execute('''SELECT id FROM fingerprint_map as map WHERE map.norm_ext_id = %s AND id != %s;''', [norm_id, self.nid])
                    
                rows = cur.fetchall()
                for row in rows:
                    related.append({'id':   struct.pack('!q', row[0]).hex()})
                return related

    def get_labels(self):
        return get_labels_for_fp(self.nid)

    # TODO: replace utls code generation with JSON-generation
    # def generate_utls_code(self):
    
    # returns a single string of the concatenated cipher suites, e.g. 'c030c029000a'
    def get_hex_cipher_suite_str(self):
        return ''.join(['%04x' % x for x in bytea_to_u16s(self.cipher_suites)])

    def get_hex_extensions_str(self):
        return ''.join(['%04x' % x for x in bytea_to_u16s(self.extensions)])

    # Note: this includes the length (so you can exact match on =...)
    def get_hex_curves_str(self):
        return ''.join(['%04x' % x for x in bytea_to_u16s(self.supported_groups)])

    def get_hex_supported_versions_str(self):
        return ''.join(['%04x' % x for x in bytea_to_u16s(self.supported_versions)])

    def get_hex_sigalgs_str(self):
        return ''.join(['%04x' % x for x in bytea_to_u16s(self.signature_algorithms)])

def lookup_fingerprint(fid: int):
    global db_conn_pool
    with db_conn_pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM fingerprints WHERE id=%s", [fid])
            row = cur.fetchone()
            if row is None:
                return None
            #fid_hex = struct.pack('!q', int(fid)).hex()

            _, tls_record_version, tls_handshake_version, cipher_suites, compression_methods, extensions, \
            supported_groups, ec_point_formats, signature_algorithms, alpn, \
            key_share, psk_key_exchange_modes, supported_versions, compress_certificate, record_size_limit = row

            return TLSFingerprint(fid). \
                set_tls_record_version(tls_record_version). \
                set_tls_handshake_version(tls_handshake_version). \
                set_cipher_suites(cipher_suites). \
                set_compression_methods(compression_methods). \
                set_extensions(extensions). \
                set_supported_groups(supported_groups). \
                set_ec_point_formats(ec_point_formats). \
                set_signature_algorithms(signature_algorithms). \
                set_alpn(alpn). \
                set_key_share(key_share). \
                set_psk_key_exchange_modes(psk_key_exchange_modes). \
                set_supported_versions(supported_versions). \
                set_compress_certificate(compress_certificate). \
                set_record_size_limit(record_size_limit)

def lookup_fingerprint_norm(fid):
    global db_conn_pool
    with db_conn_pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM fingerprints_norm_ext WHERE id=%s", [int(fid)])
            row = cur.fetchone()
            if row is None:
                return None
            #fid_hex = struct.pack('!q', int(fid)).hex()

            _, tls_record_version, tls_handshake_version, cipher_suites, compression_methods, extensions, \
            supported_groups, ec_point_formats, signature_algorithms, alpn, \
            key_share, psk_key_exchange_modes, supported_versions, compress_certificate, record_size_limit = row

            return TLSFingerprint(fid). \
                set_tls_record_version(tls_record_version). \
                set_tls_handshake_version(tls_handshake_version). \
                set_cipher_suites(cipher_suites). \
                set_compression_methods(compression_methods). \
                set_extensions(extensions). \
                set_supported_groups(supported_groups). \
                set_ec_point_formats(ec_point_formats). \
                set_signature_algorithms(signature_algorithms). \
                set_alpn(alpn). \
                set_key_share(key_share). \
                set_psk_key_exchange_modes(psk_key_exchange_modes). \
                set_supported_versions(supported_versions). \
                set_compress_certificate(compress_certificate). \
                set_record_size_limit(record_size_limit)

def get_s_diff(l1, l2):
    out = []
    for elem in diff.myers_diff(l1, l2):
        obj = {'s': elem.line, \
               'inserted': isinstance(elem, diff.Insert), \
               'removed':  isinstance(elem, diff.Remove)}
        out.append(obj)
    return out

def get_sn_diff(l1, l2):
    out = []
    for elem in diff.myers_diff(l1, l2):
        obj = {'s': elem.line['s'], \
               'n': elem.line['n'], \
               'inserted': isinstance(elem, diff.Insert), \
               'removed':  isinstance(elem, diff.Remove)}
        out.append(obj)
    return out

# routes for graphs 

@app.route('/idgraph.js/<path:path>/<divid>')
@app.route('/idgraph.js/<path:path>/<divid>?fill=<fillz>')
def idgraph(path, divid, fillz="true"):
    #fid, = struct.unpack('!q', hid.decode('hex'))
    divid = '#' + divid
    fillz = request.args.get("fill")
    if fillz is None or fillz == 'true':
        fillz = True
    else:
        fillz = False

    #path = path.replace('-', '/')
    return render_template('idgraph.js', divid=divid, path='/'+path, fill_zeros=fillz)


@app.route('/cdfgraph.js/<path:path>/<divid>')
def cdfgraph(path, divid):
    divid = '#' + divid
    return render_template('cdfgraph.js', divid=divid, path='/'+path)

@app.route('/stackgraph.js/<path:path>/<divid>')
def stackgraph(path, divid):
    divid = '#' + divid
    return render_template('stackgraph.js', divid=divid, path='/'+path)

def compare_generic(hid1, hid2, template="compare.html"):
    # fid1, = struct.unpack('!q', hid1.decode('hex')) # python 2.x
    # fid2, = struct.unpack('!q', hid2.decode('hex')) # python 2.x
    fid1 = hex_to_int64(hid1)
    fid2 = hex_to_int64(hid2)

    fp1 = lookup_fingerprint(fid1)
    fp2 = lookup_fingerprint(fid2)

    if fp1 is None:
        return 'Not found: %s' % (struct.pack('!q', fid1).hex())
    if fp2 is None:
        return 'Not found: %s' % (struct.pack('!q', fid2).hex())

    ciphers_diff = get_sn_diff(fp1.get_cipher_suites(), fp2.get_cipher_suites())
    comps_diff   = get_sn_diff(fp1.get_compression_methods(), fp2.get_compression_methods())
    curves_diff  = get_sn_diff(fp1.get_supported_groups(), fp2.get_supported_groups())
    exts_diff    = get_sn_diff(fp1.get_extensions(), fp2.get_extensions())
    pt_fmt_diff  = get_sn_diff(fp1.get_ec_point_formats(), fp2.get_ec_point_formats())
    sigs_diff    = get_s_diff(fp1.get_signature_algorithms(), fp2.get_signature_algorithms())
    alpn_diff    = get_s_diff(fp1.get_alpn(), fp2.get_alpn())
    key_share_diff              = get_sn_diff(fp1.get_key_share(), fp2.get_key_share())
    psk_key_exchange_modes_diff = get_sn_diff(fp1.get_psk_key_exchange_modes(),
                                              fp2.get_psk_key_exchange_modes())
    supported_versions_diff     = get_sn_diff(fp1.get_supported_versions(), fp2.get_supported_versions())
    cert_compression_algs_diff  = get_sn_diff(fp1.get_compress_certificate(),
                                              fp2.get_compress_certificate())
    record_size_limit_diff      = get_s_diff([str(fp1.get_record_size_limit())], \
                                             [str(fp2.get_record_size_limit())])

    rank1, seen1, frac_seen1, rank1_wk, seen1_wk, frac_seen1_wk = fp1.get_rank()
    rank2, seen2, frac_seen2, rank2_wk, seen2_wk, frac_seen2_wk = fp2.get_rank()

    return render_template(template, hid1=hid1, hid2=hid2, \
        nid1=fid1, nid2=fid2, \
        rank1=rank1, rank2=rank2, seen1=seen1, seen2=seen2, \
        frac1=frac_seen1*100, frac2=frac_seen2*100, \
        rank1_wk=rank1_wk, rank2_wk=rank2_wk, seen1_wk=seen1_wk, seen2_wk=seen2_wk, \
        frac1_wk=frac_seen1_wk*100, frac2_wk=frac_seen2_wk*100, \
        tls_ver1=fp1.get_tls_record_version(), tls_ver2=fp2.get_tls_record_version(), \
        ch_ver1=fp1.get_tls_handshake_version(), ch_ver2=fp2.get_tls_handshake_version(), \
        ciphers=fp1.get_cipher_suites(), ciphers_diff=ciphers_diff, \
        comps=fp1.get_compression_methods(), comps_diff=comps_diff, \
        supported_groups=fp1.get_supported_groups(), curves_diff=curves_diff, \
        extensions=fp1.get_extensions(), extensions_diff=exts_diff, \
        signature_algorithms=fp1.get_signature_algorithms(), sigs_diff=sigs_diff, \
        ec_point_formats=fp1.get_ec_point_formats(), pt_fmts_diff=pt_fmt_diff, \
        alpns=fp1.get_alpn(), alpn_diff=alpn_diff, \
        labels1=fp1.get_labels(), labels2=fp2.get_labels(), \
        useragents1=fp1.get_useragents(), useragents2=fp2.get_useragents(), \
        key_share_diff=key_share_diff, psk_key_exchange_modes_diff=psk_key_exchange_modes_diff, \
        supported_versions_diff=supported_versions_diff, cert_compression_algs_diff=cert_compression_algs_diff, \
        record_size_limit_diff=record_size_limit_diff)


@app.route('/compare/<hid1>/<hid2>')
def compare(hid1, hid2):
    return compare_generic(hid1, hid2)


@app.route('/compare-min/<hid1>/<hid2>')
def compare_no_header(hid1, hid2):
    return compare_generic(hid1, hid2, template="compare-no-header.html")

@app.route('/compare-mid/<hid1>/<hid2>')
def compare_mid_level(hid1, hid2):
    if hid1=='x':
        return 'Click a node to compare'
    if hid2=='x':
        return 'Click a second node to compare'
    return compare_generic(hid1, hid2, template="compare-no-header-with-graphs.html")


# This route handles things like /find/cipher/<cs> and /find/extension/<ext>
@app.route('/find/<tbl>/<hid>')
@app.route('/find/<tbl>/<hid>/<page>')
def find_generic_single(tbl, hid, page=0):
    id_n = 0
    try:
        id_n = int(hid, 16)
    except ValueError:
        return 'Bad format'

    bytea = '\\x%04x' % (id_n)

    return find_generic_helper(tbl, bytea, id_n, page, False)


@app.route('/match/<tbl>/<hid>')
@app.route('/match/<tbl>/<hid>/<page>')
def find_generic_exact(tbl, hid, page=0):
    try:
        int(hid, 16)
        if len(hid) % 2 != 0:
            return 'Bad format'
    except ValueError:
        return 'Bad format'
    bytea = '\\x' + hid

    return find_generic_helper(tbl, bytea, None, page, True)

def find_generic_helper(tbl, bytea, id_n=None, page=0, exact=False):
    global db_conn_pool
    with db_conn_pool.connection() as conn:
        with conn.cursor() as cur:
            offset = int(page)*20

            obj_d = {'extension':   (ext_dict, 'extensions'),
                    'cipher':      (cipher_dict, 'cipher_suites'),
                    'group':       (curve_dict, 'named_groups'),
                    'supported_version':     (versions_dict, 'supported_versions'),
                    'sigalg':      (None, 'sig_algs'),
                    }
            if tbl not in obj_d:
                return 'Bad table name'
            lookup_dict, column_name, = obj_d[tbl]

            id_str = 'UNKNOWN'
            thing = column_name
            comparator = 'contains'
            if not(exact) and lookup_dict is not None and id_n in lookup_dict:
                id_str = lookup_dict[id_n]
            if exact:
                id_str = bytea
                comparator = '='

            total_seen = get_total_seen_week()

            where_clause = 'where position(%%s in %s)%%%%2=1' % (column_name)
            if exact:
                where_clause = 'where %s=%%s' % (column_name)


            query = '''select * from (select fingerprints.id, %s, COALESCE(seen,0) as seen from
                    fingerprints left join mv_ranked_fingerprints_week
                    on fingerprints.id=mv_ranked_fingerprints_week.id
                    %s) as q
                    order by q.seen desc limit 20 offset %d;''' % (column_name, where_clause, offset)

            query = '''SELECT fingerprints.id, COALESCE(MIN(seen), 0) as seen, MIN(cluster_rank)
                    FROM fingerprints
                    LEFT JOIN mv_ranked_fingerprints_week ON fingerprints.id=mv_ranked_fingerprints_week.id
                    LEFT JOIN cluster_edges ON fingerprints.id=cluster_edges.source
                    %s
                    GROUP BY fingerprints.id
                    ORDER BY seen desc
                    LIMIT 20 OFFSET %d;''' % (where_clause, offset)

            cur.execute(query, (bytea,))
            rows = cur.fetchall()
            fingerprints = []
            seen_total = 0
            for row in rows:
                nid, seen, cluster_num = row
                #r['breakdown'] = bytea_to_u16_strings(row[1], lookup_dict)
                fingerprints.append({'nid': nid,
                                    'hid': hid(nid),
                                    'cluster': cluster_num,
                                    'count': seen,
                                    'frac': float(seen) / total_seen})

            # Get the totals (no limit)
            query2 = '''select count(*), sum(coalesce(seen,0)) from
                    fingerprints left join mv_ranked_fingerprints_week
                    on fingerprints.id=mv_ranked_fingerprints_week.id
                    %s''' % (where_clause)
            cur.execute(query2, (bytea,))
            rows = cur.fetchall()
            num_seen, seen_total, = rows[0]

            #collected_ext_set = set([0x000a, 0x000b, 0x000d, 0x0010, 43, 45, 51, 0x001b, 0x001c])
            #if tbl == 'extension' and id_n in collected_ext_set:

            return render_template('find.html',
                    fingerprints=fingerprints, this_seen_total=seen_total, num_seen=num_seen,
                    total_seen=total_seen,
                    id_str=id_str, id_n=id_n, tbl=tbl, thing=thing, comparator=comparator)

@app.route('/cluster.json/id/<hex_id>')
def cluster_json(hex_id):
    global db_conn_pool
    # nid, = struct.unpack('!q', hex_id.decode('hex'))
    nid = hex_to_int64(hex_id)

    with db_conn_pool.connection() as conn:
        with conn.cursor() as cur:
            # Get all the edges
            cur.execute('select * from cluster_edges where cluster_rank=(select cluster_rank\
                    from cluster_edges where source=%s limit 1);', [int(nid)])

            edges = []
            cluster_rank = None
            seen_nodes = set()
            for row in cur.fetchall():
                source, dest, lev_dist, cluster_rank = row
                edges.append({"source": hid(source),
                            "target": hid(dest),
                            "group": 1,
                            "value": lev_dist})
                seen_nodes.add(source)
                seen_nodes.add(dest)

            if cluster_rank is None:
                return '{"nodes":[], "links":[]}'

            total_seen = get_total_seen_week()

            # Get all the nodes
            cur.execute('select source, min(seen) as seen from cluster_edges\
                    left join mv_ranked_fingerprints_week on\
                        cluster_edges.source=mv_ranked_fingerprints_week.id\
                    where cluster_rank=%s group by source order by seen desc;', [int(cluster_rank)])
            nodes = []
            avail_nodes = set()
            for row in cur.fetchall():
                node_id, seen, = row

                # Size of node
                sz = 3  # size if it was not seen at all
                if seen is not None and seen != 0:
                    #sz = min(max(int(4*math.log(seen)), 5),150)
                    sz = max(int(1000*float(seen)/total_seen),5)
                group = 1
                if nid == node_id:
                    group = 2
                nodes.append({"id": hid(node_id),
                            "name": hid(node_id),
                            "group": group,
                            "value": sz})
                avail_nodes.add(node_id)

            # Sanity check
            for node in seen_nodes:
                if node not in avail_nodes:
                    # This shouldn't happen, but if it does, we can just "add" this node in a different
                    # "Error" group
                    avail_nodes.add(node)
                    nodes.append({"id": hid(node),
                                "name": hid(node),
                                "group": 1,
                                "value": 3})

            return render_template('cluster.json', nodes=nodes, links=edges)

def load_crandom_dups_obj():
    with open('/home/ubuntu/tls-fingerprint/data/crandom-dups-clusters.pickle', 'r') as f:
        return pickle.load(f)

@app.route('/crandom2.json')
def get_crandom2_json():
    edges_f, seen_map, dup_fps, crand_map = load_crandom_dups_obj()
    edges = []
    nodes = []
    uniq_nodes = set()
    # Edge between nodes if same crandom
    crand_n = 0
    for crandom, cids in crand_map.items():
        crandom = crandom[2:]
        nodes.append({'id': crandom,
                      'name': crandom,
                      'value': len(cids),
                      'group': 1})

        uniq_cids = list(set(cids))
        if len(uniq_cids) > 1:
            crand_n += 1
        for cid in uniq_cids:
            uniq_nodes.add(cid)
            edges.append({'source': hid(cid),
                          'target': crandom,
                          'group': crand_n,
                          'value': '',
                          'width': 2})

    for cid in uniq_nodes:
        seen = seen_map[cid]
        if seen == 0: seen = 1
        sz = int(3*math.log(float(seen)))
        sz = min(max(sz, 3),150)
        nodes.append({'id': hid(cid),
                      'name': hid(cid),
                      'group': 2,
                      'value': sz})

    return render_template('cluster-crandom.json', nodes=nodes, links=edges)

@app.route('/crandom.json')
def get_crandom_json():
    edges_f, seen_map, dup_fps, crand_map = load_crandom_dups_obj()
    edges = []
    nodes = []
    uniq_nodes = set()
    # Edge between nodes if same crandom
    crand_n = 0
    for crandom, cids in crand_map.items():
        uniq_cids = list(set(cids))
        if len(uniq_cids) > 1:
            crand_n += 1
        for i in range(len(uniq_cids)):
            cid1 = uniq_cids[i]
            uniq_nodes.add(cid1)
            for j in range(i+1,len(uniq_cids)):
                cid2 = uniq_cids[j]
                edges.append({"source": hid(cid1),
                              "target": hid(cid2),
                              "group": crand_n,
                              "value": crandom[2:],
                              "width": len(cids)})

    for cid in uniq_nodes:
        seen = seen_map[cid]
        if seen == 0: seen = 1
        sz = int(3*math.log(float(seen)))
        sz = min(max(sz, 3),150)
        nodes.append({'id': hid(cid),
                      'name': hid(cid),
                          'group': 1,
                          'value': sz})

    return render_template('cluster-crandom.json', nodes=nodes, links=edges)


@app.route('/cluster-crand.json')
def get_cluster_crand_json():
    edges_f, seen_map, dup_fps, crand_map = load_crandom_dups_obj()
    edges = []
    nodes = []
    avail_nodes = set()
    import random
    for edge in edges_f:
        source, dest, lev_dist, cluster_rank = edge
        edges.append({"source": hid(source),
                      "target": hid(dest),
                      "group": 1,
                      "value": lev_dist})
        avail_nodes.add(source)
        avail_nodes.add(dest)

    # populate edges from duplicate crandoms
    for crandom, cids in crand_map.items():
        cids = list(set(cids))
        for i in range(len(cids)):
            cid1 = cids[i]
            avail_nodes.add(cid1)
            for j in range(i+1,len(cids)):
                cid2 = cids[j]
                edges.append({"source": hid(cid1),
                              "target": hid(cid2),
                              "group": 2,
                              "value": 1})
    total_seen = sum(seen_map.values())
    for node in avail_nodes:
        seen = seen_map[node]
        is_dup = node in dup_fps
        if seen == 0: seen = 1
        sz = int(3*math.log(float(seen)))
        sz = min(max(sz, 3),150)
        nodes.append({'id': hid(node),
                      'name': hid(node),
                      'group': 1 if is_dup else 2,
                      'value': sz})

    return render_template('cluster.json', nodes=nodes, links=edges)

# deprecated: mv_ranked_fingerprints_week is no longer updated
def get_cluster_metadata(nid):
    global db_conn_pool
    with db_conn_pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute('''select count(*), sum(seen), min(cr) from
                (select source, min(seen) as seen, min(cluster_rank) as cr from
                cluster_edges left join mv_ranked_fingerprints_week
                    on cluster_edges.source=mv_ranked_fingerprints_week.id
                where cluster_rank=
                    (select cluster_rank from cluster_edges where source=%s limit 1)
                group by source) as q''', [int(nid)])

            row = cur.fetchone()
            if row is None:
                return (None, None, None)
            num_fps, cluster_seen, cluster_rank = row
            return (num_fps, cluster_seen, cluster_rank)

@app.route('/cluster-crandom')
def cluster_cran():
    edges_f, seen_map, dup_fps, crand_map = load_crandom_dups_obj()
    max_rank = max([e[3] for e in edges_f])
    return render_template('cluster-crand.html', fps=len(seen_map), dup_fps=len(dup_fps), n_clusters=max_rank)

@app.route('/crandom')
def crandom():
    edges_f, seen_map, dup_fps, crand_map = load_crandom_dups_obj()
    max_rank = max([e[3] for e in edges_f])
    return render_template('crandom.html', fps=len(dup_fps), dup_fps=len(dup_fps), n_clusters=max_rank)

@app.route('/crandom2')
def crandom2():
    edges_f, seen_map, dup_fps, crand_map = load_crandom_dups_obj()
    max_rank = max([e[3] for e in edges_f])
    return render_template('crandom2.html', fps=len(dup_fps), dup_fps=len(dup_fps), n_clusters=max_rank)


@app.route('/cluster/<hid>')
def cluster(hid):
    # nid, = struct.unpack('!q', hid.decode('hex'))
    nid = hex_to_int64(hid)
    global db_conn_pool
    with db_conn_pool.connection() as conn:
        with conn.cursor() as cur:
            total_seen = get_total_seen_week()

            num_fps, cluster_seen, cluster_rank = get_cluster_metadata(nid)
            if cluster_seen is None:
                return 'Not found in any clusters (possibly not in a large enough cluster)'


            cur.execute('select distinct useragent from\
                    (select distinct source from cluster_edges where cluster_rank=\
                        (select cluster_rank from cluster_edges where source=%s limit 1)) as q\
                        left join useragents on q.source=useragents.id;', [int(nid)])

            user_agents = sorted([r[0] for r in cur.fetchall() if r[0] is not None])

            return render_template('cluster.html', hid=hid, seen=cluster_seen, total=total_seen,
                    pct_seen=100*float(cluster_seen)/total_seen, fps=num_fps, cluster_id=cluster_rank,
                    user_agents=user_agents)

@app.route('/cluster.js/<hid>')
def cluster_js(hid):
    return render_template('cluster.js', hid=hid, divid="")

@app.route('/cluster-crand.js')
def cluster_crand_js():
    return render_template('cluster-crand.js')

@app.route('/crandom.js')
def crandom_js():
    return render_template('crandom.js')
@app.route('/crandom2.js')
def crandom2_js():
    return render_template('crandom2.js')

def cluster_summary():
    global db_conn_pool
    with db_conn_pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute('''select cr as cluster_rank, count(*) as num_fps, coalesce(sum(seen),0) as seen,
                        100*coalesce(sum(seen),0)/(select sum(seen) from mv_ranked_fingerprints_week) as pct,
                        (select source from cluster_edges left join mv_ranked_fingerprints_week
                            on cluster_edges.source=mv_ranked_fingerprints_week.id
                            where cluster_rank=cr order by seen desc limit 1) as largest_fp
                    from (select source, min(seen) as seen, min(cluster_rank) as cr
                        from cluster_edges left join mv_ranked_fingerprints_week
                            on cluster_edges.source=mv_ranked_fingerprints_week.id
                        group by source) as q
                    group by cr order by seen desc;''')

            data = []
            total_pct_seen = 0.0
            total_fps = 0
            for row in cur.fetchall():
                cluster_rank, num_fps, seen, conn_pct, largest_fp_id = row
                if conn_pct is None:
                    conn_pct = 0
                data.append({'largest_id': hid(largest_fp_id),
                            'num_fps': num_fps,
                            'seen': seen,
                            'pct_conns': conn_pct,
                            'cluster_num': cluster_rank})

                total_pct_seen += float(conn_pct)
                total_fps += int(num_fps)
            return (total_fps, total_pct_seen, data)

@app.route('/clusters')
def clusters():
    total_fps, total_pct_seen, clusters = cluster_summary()
    return render_template('clusters.html', clusters=clusters, total_pct_seen=total_pct_seen, total_fps=total_fps)

@app.route('/close/<hid>')
def close_ids(hid):
    # nid, = struct.unpack('!q', hid.decode('hex'))
    nid = hex_to_int64(hid)
    
    global db_conn_pool
    with db_conn_pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute('''SELECT * from mv_ranked_fingerprints where id=%s''', [int(nid)])
            row = cur.fetchone()
            if row is None:
                return 'Not found'

            _, seen, rank = row
            fp = lookup_fingerprint(nid)

            diffs = []

            nid = int(nid)
            # TODO: alpn? ec_pt_fmts?
            cur.execute('''select * from (select fingerprints.id, seen,
                            u16_lev((select cipher_suites from fingerprints where id=%s), cipher_suites) +
                            u16_lev((select extensions from fingerprints where id=%s), extensions) +
                            u16_lev((select named_groups from fingerprints where id=%s), named_groups) +
                            u8_lev((select compression_methods from fingerprints where id=%s), compression_methods) +
                            u16_lev_skiphdr((select sig_algs from fingerprints where id=%s),        sig_algs, fps, seen = row
                            if len(sig_algs) < 2:
                            continue
                            sig_algs) +
                            abs((select record_tls_version from fingerprints where id=%s) - record_tls_version) +
                            abs((select ch_tls_version from fingerprints where id=%s) - ch_tls_version)
                    as lev from mv_ranked_fingerprints left join fingerprints on mv_ranked_fingerprints.id=fingerprints.id order by lev) as q where lev < 10''', \
                            [nid, nid, nid, nid, nid, nid, nid])

            '''select fingerprints.id, seen,
                            u16_lev((select cipher_suites from fingerprints where id=3400840294346873990), cipher_suites) +
                            u16_lev((select extensions from fingerprints where id=3400840294346873990), extensions) +
                            u16_lev((select named_groups from fingerprints where id=3400840294346873990), named_groups) +
                            u8_lev((select compression_methods from fingerprints where id=3400840294346873990), compression_methods) +
                            u16_lev_skiphdr((select sig_algs from fingerprints where id=3400840294346873990), sig_algs) +
                            abs((select record_tls_version from fingerprints where id=3400840294346873990) - record_tls_version) +
                            abs((select ch_tls_version from fingerprints where id=3400840294346873990) - ch_tls_version)
                    as lev from mv_ranked_fingerprints left join fingerprints on mv_ranked_fingerprints.id=fingerprints.id order by lev, seen desc;'''

            #db.cur.execute('''SELECT * FROM mv_ranked_fingerprints limit 100''')
            rows = cur.fetchall()
            for row in rows:
                c_id, c_seen, lev_dist = row

                #c_fp = lookup_fingerprint(c_id)

                #d = fp.get_lev_dist(c_fp)
                diffs.append({'lev':lev_dist, 'id':struct.pack('!q', c_id).hex()})

            diffs = sorted(diffs, key=lambda x: x['lev'])
            return render_template('close.html', diffs=diffs, id=hid)

# Assumes data is an array like [[t0, v0], [t1, v1], [t2, v2] ...]
# and returns a similarly-shaped array, but window-averaged
def smooth_data(data, win=24):
    return zip([r[0] for r in data[win:]],
                [sum([r[1] for r in data[i:i+win]])/float(win) for i in range(len(data)-win+1)])

@app.route('/measurements/<hid>')
def measurements_hex(hid):
    # nid, = struct.unpack('!q', hid.decode('hex'))
    nid = hex_to_int64(hid)
    global db_conn_pool
    with db_conn_pool.connection() as conn:
        with conn.cursor() as cur:
            # Build graph of measurements
            cur.execute('select unixtime, count from measurements where id=%s order by unixtime', [int(nid)])
            rows = cur.fetchall()
            return render_template('measurements.csv', data=rows)


@app.route('/data/norm/<hid>')
def norm_measurements_hex(hid):
    # nid, = struct.unpack('!q', hid.decode('hex'))
    nid = hex_to_int64(hid)
    global db_conn_pool
    with db_conn_pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute('select mv_measurements_total.unixtime, 100*cast(COALESCE(count,0) as float) / cast(total as float) from mv_measurements_total left join (select * from measurements where id=%s) as m on mv_measurements_total.unixtime=m.unixtime order by unixtime', [int(nid)])
            rows = cur.fetchall()

            # Take 24-hour average (assumes each row is 1 hour)
            win = 24
            data = smooth_data(rows)
            return render_template('measurements.csv', data=data)

@app.route('/data/browsers')
def browsers_data():
    global db_conn_pool
    with db_conn_pool.connection() as conn:
        with conn.cursor() as cur:
            browsers = {'Chrome 64': [-2968298672377436309, -2003967759959048368],
                    'Chrome 58-63': [-2850568065084196667, 3400840294346873990, -2129010934376955896, 496336660199593529],
                    'Firefox 55-57': [3806443866992693068, -4010993645394274241],
                    'iOS 11': [-5935500785149131599, 3503756541338313045, -7127967423922852970],
                    'iOS 10': [8640374703234307897, 6116711302262389225, 5328249007092059224, -8009421017162168522],}

            all_ids = [b for a in browsers.values() for b in a]

            dates = []
            win = 24
            browser_data = {}

            for browser, ids in browsers.items():
                cur.execute('''SELECT mv_measurements_total.unixtime,
                                        100*cast(COALESCE(sum(count),0) AS float) / cast(min(total) AS float)
                                FROM mv_measurements_total LEFT JOIN
                                (SELECT * FROM measurements WHERE id IN %s) AS m
                                ON mv_measurements_total.unixtime=m.unixtime
                                GROUP BY mv_measurements_total.unixtime ORDER BY unixtime''', (tuple(ids),))

                rows = db.cur.fetchall()
                if len(dates) == 0:
                    dates = [r[0] for r in rows[win:]]
                browser_data[browser] = [sum([a[1] for a in rows[i:i+win]])/float(win) for i in range(len(rows)-win+1)]

            browser_keys = ['iOS 10', 'iOS 11', 'Firefox 55-57', 'Chrome 58-63', 'Chrome 64'] # ordered how we want...
            # flatten/transpose data for render
            hdr_row = ['date']
            hdr_row += browser_keys
            data = [hdr_row]
            for i in range(len(dates)):
                row = [dates[i]]
                for browser in browser_keys:
                    if len(browser_data[browser]) < len(dates):
                        return 'Ok dunno what happened: %d != %d, %s => %s' % (len(browser_data[browser]), len(dates), browser, browser_data)
                    row.append(browser_data[browser][i])
                data.append(row)

            return render_template('stacked.csv', data=data)

@app.route('/data/versions')
def version_data():
    global db_conn_pool
    with db_conn_pool.connection() as conn:
        with conn.cursor() as cur:
            versions = {768: 'ssl3.0',
                        769: 'tls1.0',
                        770: 'tls1.1',
                        771: 'tls1.2',}

            cur.execute('''select record_tls_version, ch_tls_version, mv_version_times.unixtime,
                            100*cast(sum as float) / cast(total as float) as pct
                            from mv_version_times left join mv_measurements_total
                            on mv_version_times.unixtime=mv_measurements_total.unixtime;''')
            rows = cur.fetchall()
            ver_keys = set() # list of all the 'SSL 3.0 / TLS 1.0', 'TLS 1.0 / TLS 1.1' that we've seen
            ver_data = {} # unixtime => { tls_ver/ch_ver => pct }
            for row in rows:
                tls_ver, ch_ver, utime, pct, = row
                if utime not in ver_data:
                    ver_data[utime] = {}
                if tls_ver not in versions or ch_ver not in versions:
                    #return 'Error: %d or %d not in versions' % (tls_ver, ch_ver)
                    continue
                ver_str = '%s / %s' % (versions[tls_ver], versions[ch_ver])
                ver_data[utime][ver_str] = pct
                ver_keys.add(ver_str)


            # Versions we care about
            ver_keys = ['tls1.0 / tls1.2', 'tls1.2 / tls1.2', 'tls1.0 / tls1.0', 'ssl3.0 / tls1.2']

            ver_data_items = sorted(ver_data.items())

            win = 24
            dates = [a[0] for a in ver_data_items[win:]]
            ver_data_smooth = {}
            for ver in ver_keys:
                ver_data_smooth[ver] = [sum([a[1][ver] for a in ver_data_items[i:i+win] if ver in a[1]])/float(win) for i in range(len(ver_data_items)-win+1)]

            hdr_row = ['date']
            hdr_row += ver_keys
            data = [hdr_row]
            for i in range(len(dates)):
                row = [dates[i]]
                for ver in ver_keys:
                    row.append(ver_data_smooth[ver][i])
                data.append(row)

            return render_template('stacked.csv', data=data)

@app.route('/data/generic/<thing>')
def generic_data(thing):
    global db_conn_pool
    with db_conn_pool.connection() as conn:
        with conn.cursor() as cur:
            thing_queries= {
                'new-fingerprints':     ('select new.t, count(*) from (select min(unixtime) as t, id from \
                                        measurements group by id order by t asc) as new group by new.t',
                                        'measurements.csv'),
                'unique-fingerprints':  ('select unixtime, count(*) from measurements group by unixtime \
                                        order by unixtime asc',
                                        'measurements.csv'),
                'total-measurements':   ('select unixtime, sum(count) from measurements group by unixtime \
                                        order by unixtime asc',
                                        'measurements.csv'),
                'cumulative-measurements':     ('select unixtime, sum(total) OVER (ORDER BY unixtime) AS ct \
                                        FROM mv_measurements_total',
                                        'measurements.csv'),
                'cumulative-unique':    ('select n.unixtime, sum(count) over (order by unixtime) as ct \
                                        from (select unixtime, count(*) from \
                                            (select min(unixtime) as unixtime, id from measurements group by id) \
                                            as m group by unixtime) as n',
                                        'measurements.csv'),
                'cumulative-unique-1k':    ('select n.first, sum(count) over (order by first) as ct from \
                                                (select t.first, count(*) from (select first, q.id from mv_ranked_fingerprints \
                                                    left join (select min(unixtime) as first, id from measurements group by id) as q\
                                                    on mv_ranked_fingerprints.id=q.id where seen>1000) as t \
                                                group by first order by first asc) as n',
                                        'measurements.csv'),
                'cumulative-unique-10k':    ('select n.first, sum(count) over (order by first) as ct from \
                                                (select t.first, count(*) from (select first, q.id from mv_ranked_fingerprints \
                                                    left join (select min(unixtime) as first, id from measurements group by id) as q\
                                                    on mv_ranked_fingerprints.id=q.id where seen>10000) as t \
                                                group by first order by first asc) as n',
                                        'measurements.csv'),
                'cdf-fingerprints':     ('select id, cast(cumul as float)/cast(total as float) from \
                                        (select id, seen, sum(seen) over (order by seen desc) as cumul, \
                                        (select sum(seen) from mv_ranked_fingerprints) as total from \
                                        mv_ranked_fingerprints order by rank) as i limit 5000;',
                                        'cdf.csv'),
                'cdf-sfingerprints':    ('select sid, cast(cumul as float)/cast(total as float) from \
                                        (select sid, seen, sum(seen) over (order by seen desc) as cumul, \
                                        (select sum(count) from smeasurements) as total from \
                                            (select sid, sum(count) as seen \
                                            from smeasurements group by sid order by seen desc \
                                            ) as q \
                                        ) as i limit 5000;',
                                        'cdf.csv'),
                'sniless-cdf':          ('select id, cast(cumul as float)/cast(total as float) as cdf from \
                                            (select mv_ranked_fingerprints.id, seen, sum(seen) over (order by seen desc) as cumul, \
                                            (select sum(seen) from mv_sniless_fps \
                                            left join mv_ranked_fingerprints on mv_sniless_fps.id=mv_ranked_fingerprints.id \
                                            ) as total \
                                            from mv_sniless_fps left join mv_ranked_fingerprints \
                                            on mv_sniless_fps.id=mv_ranked_fingerprints.id order by rank \
                                            ) as q;',
                                        'cdf.csv'),
            }
            if thing in thing_queries:
                query, template = thing_queries[thing]
                cur.execute(query)
                rows = cur.fetchall()
                return render_template(template, data=rows)

@app.route('/data/find/<tbl>/<hid>')
def param_generic_data(tbl, hid):
    # TODO TK

    global db_conn_pool
    with db_conn_pool.connection() as conn:
        with conn.cursor() as cur:
            try:
                id_n = int(hid, 16)
            except ValueError:
                return 'Bad format'

            bytea = '\\x%04x' % (id_n)

            obj_d = {'extension':   (ext_dict, 'extensions'),
                    'cipher':      (cipher_dict, 'cipher_suites'),
                    'group':       (curve_dict, 'named_groups'),
                    'supported_version':     (versions_dict, 'supported_versions'),
                    }
            if tbl not in obj_d:
                return 'Bad table name'
            lookup_dict, column_name, = obj_d[tbl]

            query = '''select t.unixtime, COALESCE(100*cast(n as float)/total, 0) from
                    (select unixtime, sum(count) as n from
                        (select fingerprints.id, COALESCE(seen,0) as n from
                            fingerprints left join mv_ranked_fingerprints
                            on fingerprints.id=mv_ranked_fingerprints.id
                            where position(%%s in %s)%%%%2=1
                        ) as q
                        left join measurements on q.id=measurements.id
                        where unixtime is not NULL group by unixtime order by unixtime
                    ) as t
                    left join mv_measurements_total on t.unixtime=mv_measurements_total.unixtime
                    order by unixtime''' % (column_name)

            cur.execute(query, [bytea])
            rows = cur.fetchall()
            data = smooth_data(rows)
            #data = rows

            return render_template('measurements.csv', data=data, tbl=tbl)



@app.route('/total')
def total():
    return render_template('total.html')

@app.route('/label/<lid>')
def label_list(lid):
    return 'Not implemented'

@app.route('/weak-ciphers')
def weak_ciphers():
    global db_conn_pool
    with db_conn_pool.connection() as conn:
        with conn.cursor() as cur:
            md5_ids = []
            sha1_ids = []
            export_ids = []
            rc4_ids = []
            des_ids = []
            des3_ids = []
            fallback_ids = [0x5600]
            for k, v in cipher_dict.items():
                if '_MD5' in v:
                    md5_ids.append(k)
                if v.endswith('_SHA'):
                    sha1_ids.append(k)
                if 'EXPORT' in v:
                    export_ids.append(k)
                if '_RC4_' in v:
                    rc4_ids.append(k)
                if '_DES_' in v:
                    des_ids.append(k)
                if '_3DES_' in v:
                    des3_ids.append(k)

            # { cipher_id => (num_fps, num_seen) }
            md5_breakdown    = {c: (0, 0) for c in md5_ids}
            sha_breakdown    = {c: (0, 0) for c in sha1_ids}
            export_breakdown = {c: (0, 0) for c in export_ids}
            rc4_breakdown    = {c: (0, 0) for c in rc4_ids}
            des_breakdown    = {c: (0, 0) for c in des_ids}
            des3_breakdown   = {c: (0, 0) for c in des3_ids}
            fallback_breakdown= {c: (0, 0) for c in fallback_ids}

            md5_num, md5_seen = 0, 0
            sha_num, sha_seen = 0, 0
            export_num, export_seen = 0, 0
            rc4_num, rc4_seen = 0, 0
            des_num, des_seen = 0, 0
            des3_num, des3_seen = 0, 0
            fallback_num, fallback_seen = 0, 0

            tot_fps, tot_seen = 0, 0

            cur.execute('''SELECT cipher_suites, count(*) as fps, sum(seen) as seen FROM mv_ranked_fingerprints_week
                LEFT JOIN fingerprints ON mv_ranked_fingerprints_week.id=fingerprints.id
                WHERE seen > 1
                GROUP BY cipher_suites ORDER BY seen DESC;''')
            for row in cur.fetchall():
                ciphers, fps, seen = row

                # These track if we had _any_ cipher suites in these weak modes
                # to avoid double counting in totals (e.g. two distinct MD5 cipher suites)
                in_md5, in_sha, in_export, in_rc4, in_des, in_des3, in_fallback = False, False, False, False, False, False, False

                # This tracks the ciphers this cipher suite has
                # to avoid double counting in breakdown (e.g. two of the same cipher suite)
                already_counted = set()

                for cipher in bytea_to_u16s(ciphers):

                    # Don't double count
                    if cipher in already_counted:
                        continue
                    already_counted.add(cipher)

                    def update_breakdown(cipher, fps, seen, ids, breakdown):
                        if cipher in ids:
                            n_fps, n_seen = breakdown[cipher]
                            n_fps += 1
                            n_seen += seen
                            breakdown[cipher] = (n_fps, n_seen)
                            return True
                        return False

                    in_md5    |= update_breakdown(cipher, fps, seen, md5_ids, md5_breakdown)
                    #in_sha    |= update_breakdown(cipher, fps, seen, sha1_ids, sha_breakdown)
                    in_rc4    |= update_breakdown(cipher, fps, seen, rc4_ids, rc4_breakdown)
                    in_export |= update_breakdown(cipher, fps, seen, export_ids, export_breakdown)
                    in_des    |= update_breakdown(cipher, fps, seen, des_ids, des_breakdown)
                    in_des3   |= update_breakdown(cipher, fps, seen, des3_ids, des3_breakdown)
                    in_fallback |= cipher in fallback_ids #update_breakdown(cipher, fps, seen, fallback_ids, fallback_breakdown)

                if in_md5:
                    md5_num  += fps
                    md5_seen += seen
                if in_sha:
                    sha_num  += fps
                    sha_seen += seen
                if in_rc4:
                    rc4_num  += fps
                    rc4_seen += seen
                if in_export:
                    export_num  += fps
                    export_seen += seen
                if in_des:
                    des_num  += fps
                    des_seen += seen
                if in_des3:
                    des3_num  += fps
                    des3_seen += seen
                if in_fallback:
                    fallback_num  += fps
                    fallback_seen += seen

                tot_seen += seen
                tot_fps += fps

            # Reorganizes and sorts a breakdown dictionary
            # into an array of dictionaries, sorted by seen desc
            def sort_breakdown(breakdown):
                return sorted([{'id': c[0],
                                'name': '%s (0x%04x)' % (cipher_dict[c[0]], c[0]),
                                'fps': c[1][0],
                                'seen': c[1][1]} for c in breakdown.items()],
                            key=lambda x: x['seen'], reverse=True)

            md5_breakdown      = sort_breakdown(md5_breakdown)
            #sha_breakdown      = sort_breakdown(sha_breakdown)
            export_breakdown   = sort_breakdown(export_breakdown)
            rc4_breakdown      = sort_breakdown(rc4_breakdown)
            des_breakdown      = sort_breakdown(des_breakdown)
            des3_breakdown     = sort_breakdown(des3_breakdown)
            #fallback_breakdown = sort_breakdown(fallback_breakdown)

            return render_template('weak.html', tot_num=float(tot_fps), tot_seen=float(tot_seen),
                md5_num=md5_num, md5_seen=md5_seen,
                md5_breakdown=md5_breakdown,
                sha_num=sha_num, sha_seen=sha_seen,
                export_num=export_num, export_seen=export_seen,
                export_breakdown=export_breakdown,
                rc4_num=rc4_num, rc4_seen=rc4_seen,
                rc4_breakdown=rc4_breakdown,
                des_num=des_num, des_seen=des_seen,
                des_breakdown=des_breakdown,
                des3_num=des3_num, des3_seen=des3_seen,
                des3_breakdown=des3_breakdown,
                fallback_num=fallback_num, fallback_seen=fallback_seen)

@app.route('/sig-algs')
def sig_algs():
    global db_conn_pool
    with db_conn_pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute('''SELECT sig_algs, count(*) as fps, sum(seen) as seen
                    FROM mv_ranked_fingerprints_week
                    LEFT JOIN fingerprints ON mv_ranked_fingerprints_week.id=fingerprints.id
                    GROUP BY sig_algs ORDER BY seen DESC;''')

            totals = {} # {sig_alg} => (fps, seen)

            tot_fps = 0
            tot_seen = 0
            for row in cur.fetchall():
                sig_algs, fps, seen = row

                already_counted = set()

                for sa in parse_sig_algs(sig_algs):
                    # Don't double count
                    if sa['n'] in already_counted:
                        continue
                    already_counted.add(sa['n'])

                    # Update totals
                    if sa['str'] not in totals:
                        totals[sa['str']] = (0, 0)
                    n_fps, n_seen = totals[sa['str']]
                    n_fps += fps
                    n_seen += seen
                    totals[sa['str']] = (n_fps, n_seen)

                tot_fps += fps
                tot_seen += seen


            out = sorted([{'name': c[0],
                    'fps': c[1][0],
                    'seen': c[1][1]} for c in totals.items()],
                key=lambda x: x['seen'], reverse=True)


            return render_template('sig-algs.html', sig_algs=out, tot_fps=float(tot_fps), tot_seen=float(tot_seen))

def format_seen(seen):
    if seen > 1000000000:
        if seen < 10000000000:
            return '%.1fB' % (seen / 1000000000.0)
        return '%dB' % (seen / 1000000000)
    elif seen > 1000000:
        if seen < 10000000:
            return '%.1fM' % (seen / 1000000.0)
        return '%dM' % (seen / 1000000)
    elif seen > 1000:
        if seen < 10000:
            return '%.1fK' % (seen / 1000.0)
        return '%dK' % (seen / 1000)
    elif seen < 100:
        return '< 100'
    else:
        return seen

@app.route('/browsers')
def browsers():
    return render_template('browsers.html')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/get-fp-stats')
def get_fp_stats():
    global db_conn_pool
    with db_conn_pool.connection() as conn:
        with conn.cursor() as cur:
            # get GET params
            normid = request.args.get('normid')
            if normid is None:
                return Response(status=400)
            # hex to int
            # normid, = struct.unpack('!q', normid.decode('hex')) # python 2.x
            normid = hex_to_int64(normid)
            
            print("get_fp_stats: ", normid)

            fp_stat = api.get_fp_stat(cur, int(normid))
            if fp_stat is None:
                return Response(status=404)
            id, seen, rank, cluster, cluster_fps, cluster_seen = fp_stat

            cur.execute('''select sum(seen) from mv_ranked_fingerprints_week''')
            row = cur.fetchone()
            total_seen = 1.0
            if row is not None and row[0] is not None:
                total_seen = row[0]
            fp_stat_dict = {
                'seen': int(seen),
                'rank': int(rank),
                'frac_seen': float(seen) / int(total_seen)
            }
            return jsonify(fp_stat_dict)


@app.route('/add-user-agent', methods=['POST'])
def add_user_agent():
    if request.method == 'POST':
        global db_conn_pool
        with db_conn_pool.connection() as conn:
            # get useragent and fingerprint id from POST body
            ua = request.form['useragent']
            id = request.form['id']
            normid = request.form['normid']
            if ua is None or id is None or normid is None:
                return Response(status=400)

            # hex to int
            # id, = struct.unpack('!q', id.decode('hex'))
            # normid, = struct.unpack('!q', normid.decode('hex'))
            id = hex_to_int64(id)
            normid = hex_to_int64(normid)
            api.record_useragent(conn, id, normid, ua)
            return Response(status=204)
    else:
        return Response(status=405) # method not allowed

@app.route('/id/<fid>') # hex
def fingerprint_hex(fid):
    # fid, = struct.unpack('!q', fid.decode('hex'))
    fid = hex_to_int64(fid)
    return fingerprint(fid)

@app.route('/nid/<fid>') # decimal
def fingerprint(fid):
    global db_conn_pool
    with db_conn_pool.connection() as conn:
        with conn.cursor() as cur:
            times = [time.time()]
            f = lookup_fingerprint(int(fid))    # 82 ms
            if f is None:
                return 'Not found'
            fid_hex = struct.pack('!q', int(fid)).hex()

            times.append(time.time())
            rank, seen, frac_seen, rank_wk, seen_wk, frac_seen_wk = f.get_rank()     # 250 ms, 130 ms with caching of total_seen()
            times.append(time.time())

            if seen < 100:
                frac_seen = 0.00
            seen = format_seen(seen)
            seen_wk = format_seen(seen_wk)

            cur.execute("SELECT count(*) from fingerprints_norm_ext") # 48 ms
            rows = cur.fetchall()
            uniq = rows[0][0]

            cur.execute("SELECT count(*) from mv_ranked_fingerprints_norm_ext_week")
            rows = cur.fetchall()
            uniq_wk = rows[0][0]

            times.append(time.time())
            normid = f.get_norm_id()
            # convert to hex
            normid = struct.pack('!q', normid).hex()
            times.append(time.time())
            tls_ver = f.get_tls_record_version()  #
            times.append(time.time())
            ch_ver = f.get_tls_handshake_version()
            times.append(time.time())
            ciphers = f.get_cipher_suites()
            times.append(time.time())
            comps = f.get_compression_methods()
            times.append(time.time())
            exts = f.get_extensions()
            times.append(time.time())
            alpns = f.get_alpn()
            times.append(time.time())
            supported_groups = f.get_supported_groups()
            times.append(time.time())
            signature_algorithms = f.get_signature_algorithms()
            times.append(time.time())
            ec_point_formats = f.get_ec_point_formats()
            times.append(time.time())
            useragents = f.get_useragents()  # 128 ms
            times.append(time.time())
            ciphers_str = f.get_hex_cipher_suite_str()  #
            times.append(time.time())
            related=f.get_related()     # 372 ms, 130 ms with > clause
            times.append(time.time())

            key_share = f.get_key_share()
            psk_key_exchange_modes = f.get_psk_key_exchange_modes()
            supported_versions = f.get_supported_versions()
            compress_certificate = f.get_compress_certificate()
            record_size_limit = f.get_record_size_limit()

            labels = f.get_labels()

            ext_str = f.get_hex_extensions_str()
            curves_str = f.get_hex_curves_str()
            version_str = f.get_hex_supported_versions_str()
            sigalgs_str = f.get_hex_sigalgs_str()

            times = [times[i]-times[i-1] for i in range(1, len(times))]

            # TODO: add JSON generation
            # utls_code_prefix, utls_code_body_unescaped, utls_code_suffix = f.generate_utls_code()
            
            ## cluster deprecated
            # cluster_fps, cluster_seen, cluster_rank = get_cluster_metadata(fid)
            # cluster_pct = 100.0*frac_seen_wk
            # if cluster_seen != None:
            #     cluster_pct = 100*float(cluster_seen)/get_total_seen_week()
        
            return render_template('id.html', id=fid_hex, normid=normid, 
                            seen=seen, frac=100.0*frac_seen, 
                            seen_wk=seen_wk, frac_wk=100.0*frac_seen_wk, 
                            rank=rank, unique=uniq, 
                            rank_wk=rank_wk, unique_wk=uniq_wk, 
                            tls_ver=tls_ver, 
                            ch_ver=ch_ver, 
                            ciphers=ciphers, ciphers_str=ciphers_str, 
                            comps=comps, 
                            ext_str=ext_str, extensions=exts, 
                            supported_groups=supported_groups, curves_str=curves_str, \
                            signature_algorithms=signature_algorithms, sigalgs_str=sigalgs_str, \
                            ec_point_formats=ec_point_formats, 
                            alpns=alpns, 
                            key_share=key_share, 
                            psk_key_exchange_modes=psk_key_exchange_modes,
                            supported_versions=supported_versions, version_str=version_str,
                            compress_certificate=compress_certificate,
                            record_size_limit=record_size_limit,
                            nid=fid, 
                            related=related, 
                            labels=labels, 
                            useragents=useragents, 
                            times=times,
                        )

@app.route('/id/N/<fid>') # hex
def fingerprint_norm_hex(fid):
    # fid, = struct.unpack('!q', fid.decode('hex')) # python 2.x
    fid = hex_to_int64(fid)
    return fingerprint_norm(fid)

@app.route('/nid/N/<fid>') # decimal
def fingerprint_norm(fid):
    global db_conn_pool
    with db_conn_pool.connection() as conn:
        with conn.cursor() as cur:

            times = [time.time()]
            f = lookup_fingerprint_norm(int(fid))    # 82 ms
            if f is None:
                return 'Not found'
            fid_hex = struct.pack('!q', int(fid)).hex()

            times.append(time.time())
            rank, seen, frac_seen, rank_wk, seen_wk, frac_seen_wk = f.get_rank()     # 250 ms, 130 ms with caching of total_seen()
            times.append(time.time())

            if seen < 100:
                frac_seen = 0.00
            seen = format_seen(seen)
            seen_wk = format_seen(seen_wk)

            # count unique normalized fingerprints
            cur.execute("SELECT count(*) from fingerprints_norm_ext") # 48 ms
            rows = cur.fetchall()
            uniq = rows[0][0]

            cur.execute("SELECT count(*) from mv_ranked_fingerprints_norm_ext_week") # TODO: optimize
            rows = cur.fetchall()
            uniq_wk = rows[0][0]

            times.append(time.time())
            tls_ver = f.get_tls_record_version()  #
            times.append(time.time())
            ch_ver = f.get_tls_handshake_version()
            times.append(time.time())
            ciphers = f.get_cipher_suites()
            times.append(time.time())
            comps = f.get_compression_methods()
            times.append(time.time())
            exts = f.get_extensions()
            times.append(time.time())
            alpns = f.get_alpn()
            times.append(time.time())
            supported_groups = f.get_supported_groups()
            times.append(time.time())
            signature_algorithms = f.get_signature_algorithms()
            times.append(time.time())
            ec_point_formats = f.get_ec_point_formats()
            times.append(time.time())
            useragents = f.get_useragents()  # 128 ms
            times.append(time.time())
            ciphers_str = f.get_hex_cipher_suite_str()  #
            times.append(time.time())
            related=f.get_related()     # 372 ms, 130 ms with > clause
            times.append(time.time())

            key_share = f.get_key_share()
            psk_key_exchange_modes = f.get_psk_key_exchange_modes()
            supported_versions = f.get_supported_versions()
            compress_certificate = f.get_compress_certificate()
            record_size_limit = f.get_record_size_limit()

            labels = f.get_labels()

            ext_str = f.get_hex_extensions_str()
            curves_str = f.get_hex_curves_str()
            version_str = f.get_hex_supported_versions_str()
            sigalgs_str = f.get_hex_sigalgs_str()

            times = [times[i]-times[i-1] for i in range(1, len(times))]

            # utls_code_prefix, utls_code_body_unescaped, utls_code_suffix = f.generate_utls_code()
        
            ## clustering deprecated
            # cluster_fps, cluster_seen, cluster_rank = get_cluster_metadata(fid)
            # cluster_pct = 100.0*frac_seen_wk
            # if cluster_seen != None:
            #     cluster_pct = 100*float(cluster_seen)/get_total_seen_week()


            return render_template('nid.html', id=fid_hex, 
                        seen=seen, frac=100.0*frac_seen, 
                        seen_wk=seen_wk, frac_wk=100.0*frac_seen_wk, 
                        rank=rank, unique=uniq, 
                        rank_wk=rank_wk, unique_wk=uniq_wk, 
                        tls_ver=tls_ver, 
                        ch_ver=ch_ver, 
                        ciphers=ciphers, ciphers_str=ciphers_str, 
                        comps=comps, 
                        ext_str=ext_str, extensions=exts, 
                        supported_groups=supported_groups, curves_str=curves_str, \
                        signature_algorithms=signature_algorithms, sigalgs_str=sigalgs_str, \
                        ec_point_formats=ec_point_formats, 
                        alpns=alpns, 
                        key_share=key_share, 
                        psk_key_exchange_modes=psk_key_exchange_modes,
                        supported_versions=supported_versions, version_str=version_str,
                        compress_certificate=compress_certificate,
                        record_size_limit=record_size_limit,
                        nid=fid, 
                        related=related, 
                        labels=labels, 
                        useragents=useragents, 
                        times=times,
                    )

#def application(env, start_response):
#    start_response('200 OK', [('Content-Type','text/html')])
#    return [b"Hello World"]


@app.route('/session-tickets')
def session_tickets():
    global db_conn_pool
    with db_conn_pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute('''select sum(seen), (select sum(seen) from mv_ranked_fingerprints_norm_ext_week) from
                        fingerprints_norm_ext left join mv_ranked_fingerprints_norm_ext_week on fingerprints_norm_ext.id=mv_ranked_fingerprints_norm_ext_week.id where position('\\x0023' in normalized_extensions)%2=1;''')
            seen, tot_seen = cur.fetchall()[0]
            pct_tickets = 100*float(seen)/float(tot_seen)

            cur.execute('''select size, round((100*cast(sum(count) as decimal) / (select sum(count) from ticket_sizes_norm_ext)), 2) as c from ticket_sizes_norm_ext group by size order by c desc LIMIT 1000;''')

            data = []
            for i, row in enumerate(cur.fetchall()):
                size, pct_conns = row
                data.append({'rank': i+1, 'size': size, 'pct_conns': pct_conns})

            return render_template('tickets.html', data=data, pct_tickets=pct_tickets)

def get_generic_top(column_name, thing_dict, top_n=None, thing_iter=bytea_to_u16s):
    global db_conn_pool
    with db_conn_pool.connection() as conn:
        with conn.cursor() as cur:
            query = '''select fingerprints.id, fingerprints.''' + column_name + ''', mv_ranked_fingerprints_week.seen
                            from mv_ranked_fingerprints_week left join fingerprints on mv_ranked_fingerprints_week.id=fingerprints.id
                            where seen > 10 order by seen desc;'''

            cur.execute(query)

            things = {}
            tot_seen = 0
            tot_fps = 0
            for row in cur.fetchall():
                nid, row_things, seen, = row
                this_fp_things = set()
                for thing in thing_iter(row_things):
                    # Don't double count
                    if thing in this_fp_things:
                        continue
                    this_fp_things.add(thing)

                    if thing not in things:
                        things[thing] = (0, 0)
                    t_fps, t_seen = things[thing]
                    t_fps += 1
                    t_seen += seen
                    things[thing] = (t_fps, t_seen)
                tot_seen += seen

            # sort by seen desc
            data = []
            i = 1
            for thing_id, value in sorted(things.items(), key=lambda x: x[1][1], reverse=True):
                fps, seen = value
                data.append({'rank': i,
                            'id': thing_id,
                            'name': thing_dict[thing_id] if thing_id in thing_dict else 'Unknown',
                            'fps': fps,
                            'seen': seen,
                            'frac': 100*float(seen)/tot_seen})
                i += 1
                if top_n is not None and i > top_n:
                    break
            return data

def get_top_selected_ciphers():
    global db_conn_pool
    with db_conn_pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute('''select cipher_suite, count(distinct sid), count(distinct cid), cast(sum(count) as float) / (select sum(count) from smeasurements) as frac
                from sfingerprints left join smeasurements on sfingerprints.id=smeasurements.sid
                group by cipher_suite order by sum(count) desc;''')
            data = []
            for row in cur.fetchall():
                cs, uniq_sids, uniq_cids, f_conns, = row
                if cs < 0:
                    cs += 65536     # HACK to int16 -> uint16

                obj = {}
                obj['id'] = cs
                obj['name'] = 'UNKNOWN'
                if cs in cipher_dict:
                    obj['name'] = cipher_dict[cs]
                obj['sids'] = uniq_sids
                obj['cids'] = uniq_cids
                obj['f_conns'] = f_conns
                data.append(obj)
            return data

# Returns a table of top cipher suites, and how often they are selected
# [{'id': cipher_suite_id, 'name': 'TLS_...', 'fps': num_fingerprints, 'seen': connections,
#   'frac': %connections, 'selected_f': %selected conns, 'selected_sids': num_sfingerprints},..]
def get_top_ciphers():
    top_ciphers = get_generic_top('cipher_suites', cipher_dict)
    selected_ciphers = get_top_selected_ciphers()
    selected = {}    # cipher_suite_id => %connections selected
    for s in selected_ciphers:
        selected[s['id']] = (s['f_conns'], s['sids'])

    data = []
    for cipher in top_ciphers:
        cid = cipher['id']
        if cid in selected:
            f_conns, sids = selected[cid]
            cipher['selected_f'] = 100*f_conns
            cipher['selected_sids'] = sids
        else:
            cipher['selected_f'] = 0
            cipher['selected_sids'] = 0

    return top_ciphers


def get_version_breakdown():
    global db_conn_pool
    with db_conn_pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute('select record_tls_version, ch_tls_version, supported_versions, coalesce(sum(seen),0) from\
                    fingerprints left join mv_ranked_fingerprints_week\
                    on fingerprints.id=mv_ranked_fingerprints_week.id\
                    group by record_tls_version, ch_tls_version, supported_versions order by coalesce desc;')

            versions = {}   # (min, max => seen
            max_versions = {}   # max => seen
            for row in cur.fetchall():
                rec_ver, ch_ver, supported_versions, seen = row
                min_ver = rec_ver
                max_ver = ch_ver
                sup_vers = bytea_to_u16s(supported_versions)
                if ch_ver == 0x0303 and len(sup_vers)>0:
                    # TLS 1.3, get max/min version from supported versions
                    max_ver = sup_vers[0]   # highest priority
                    min_ver = sup_vers[-1]  # lowest priority?
                    if sup_vers[0] == 0x0a0a and len(sup_vers) > 1:
                        max_ver = sup_vers[1]
                ver = (min_ver, max_ver)

                if ver not in versions:
                    versions[ver] = 0
                if max_ver not in max_versions:
                    max_versions[max_ver] = 0
                versions[ver] += seen
                max_versions[max_ver] += seen

            total = get_total_seen_week()
            out = []
            for ver in versions.keys():
                min_ver, max_ver = ver
                seen = versions[ver]
                out.append({'min_n': min_ver,
                            'max_n': max_ver,
                            'min_s': versions_dict[min_ver] if min_ver in versions_dict else "Unknown",
                            'max_s': versions_dict[max_ver] if max_ver in versions_dict else "Unknown",
                            'seen': seen,
                            'pct':  100*float(seen)/total})

            max_out = []
            for ver in max_versions.keys():
                seen = max_versions[ver]
                max_out.append({'n': ver,
                                's': versions_dict[ver] if ver in versions_dict else "Unknwon",
                                'seen': seen,
                                'pct':  100*float(seen)/total})
            out = sorted(out, key=lambda x: x['seen'], reverse=True)
            max_out = sorted(max_out, key=lambda x: x['seen'], reverse=True)
            return out, max_out

# removed top-unchosen-ciphers due to performance issues

@app.route('/top/fingerprints')
#@cache.cached(key_prefix="top1", timeout=3*3600)
def top_fingerprints():
    top_ids = get_top_fps()
    return render_template('top-fingerprints.html', top_ids=top_ids)

@app.route('/top/N/fingerprints')
#@cache.cached(key_prefix="top1", timeout=3*3600)
def top_norm_fingerprints():
    top_norm_ids = get_top_norm_fps()
    top_ciphers = []

    return render_template('top-norm-fingerprints.html', top_ids=top_norm_ids, top_ciphers=top_ciphers)

# add top normalized fps
@app.route('/top/groups')
def groups():
    data = get_generic_top('named_groups', curve_dict)
    return render_template('groups.html', top_groups=data)

@app.route('/top/extensions')
def extensions():
    data = get_generic_top('extensions', ext_dict)
    return render_template('extensions.html', top_exts=data, collected=collected_ext_set)

@app.route('/top/versions')
def versions():
    data = get_generic_top('supported_versions', versions_dict)
    min_max_versions, max_supported_versions = get_version_breakdown()
    return render_template('versions.html', top_versions=data, max_supported_versions=max_supported_versions)

@app.route('/top/ciphers')
def ciphers():
   return render_template('ciphers.html', top_ciphers=get_top_ciphers())

@app.route('/top')
def top():
    top_versions = get_generic_top('supported_versions', versions_dict, top_n=5)
    top_groups = get_generic_top('named_groups', curve_dict, top_n=5)
    top_exts = get_generic_top('extensions', ext_dict, top_n=5)
    top_ciphers = get_top_ciphers()[:5]
    # get_generic_top('cipher_suites', cipher_dict, top_n=5)
    top_ids = get_top_fps()[:5]
    top_norm_ids = get_top_norm_fps()[:5]
    total_cluster_fps, total_cluster_pct_seen, clusters = cluster_summary()

    return render_template('top-summary.html', top_versions=top_versions,
            top_exts=top_exts, top_groups=top_groups, top_ids=top_ids, top_norm_ids=top_norm_ids,
            top_ciphers=top_ciphers, clusters=clusters[:5])


@app.route('/server-ciphers')
def server_ciphers():

    return render_template('server-ciphers.html', data=get_top_selected_ciphers())


@app.route('/alpn')
def alpn():
    global db_conn_pool
    with db_conn_pool.connection() as conn:
        with conn.cursor() as cur:
            total_seen = get_total_seen()
            total_fps = get_total_fps()

            LIMIT_ROWS = 20

            cur.execute('''select count(*), coalesce(sum(seen), 0), alpn
                            from mv_ranked_fingerprints_norm_ext left join fingerprints_norm_ext
                            on fingerprints_norm_ext.id=mv_ranked_fingerprints_norm_ext.id
                            group by alpn order by coalesce(sum(seen),0) desc;''')

            client_alpns = []
            popular_alpns = {}   # 'alpn': (num_fps, seen)

            n = 0

            for row in cur.fetchall():
                num_fps, seen, alpn, = row
                try:
                    alpn_list = parse_alpns(alpn)
                except IndexError:
                    print('Error parsing alpn: %s' % (''.join(['%02x' % c for c in alpn])))
                    continue

                for alpn in alpn_list:
                    if alpn not in popular_alpns:
                        popular_alpns[alpn] = (0, 0)
                    a, b, = popular_alpns[alpn]
                    a += num_fps
                    b += seen
                    popular_alpns[alpn] = (a, b)

                if n > -1 and n < LIMIT_ROWS:
                    obj = {'num_fps': num_fps,
                        'seen': seen,
                        'alpns': alpn_list,
                        'frac_fp': float(num_fps)/total_fps,
                        'frac_seen': float(seen)/total_seen}
                    client_alpns.append(obj)
                    n += 1

            pop_alpns = []
            for alpn, n in sorted(popular_alpns.items(), key=lambda x: x[1][1], reverse=True)[:LIMIT_ROWS]:
                obj = {'alpn': alpn,
                        'num_fps': n[0],
                        'seen': n[1],
                        'frac_fp': float(n[0])/total_fps,
                        'frac_seen': float(n[1])/total_seen}
                pop_alpns.append(obj)

            cur.execute('''select count(*), sum(count) from smeasurements''')
            total_fps, total_seen, = cur.fetchall()[0]

            cur.execute('''select count(*), sum(count), alpn
                    from sfingerprints left join smeasurements
                    on sfingerprints.id=smeasurements.sid
                    group by alpn order by sum(count) desc''')

            selected_alpns = []
            for row in cur.fetchall():
                num_fps, seen, alpn, = row
                alpn_list = parse_alpns(alpn)    # Should just return one

                alpn = ''
                if len(alpn_list) > 0:
                    alpn = alpn_list[0]
                obj = {'alpn': alpn,
                        'num_fps': num_fps,
                        'seen': seen,
                        'frac_fp': float(num_fps)/total_fps,
                        'frac_seen': float(seen)/total_seen}
                selected_alpns.append(obj)

            return render_template('alpn.html', client_alpns=client_alpns,
                    popular_alpns=pop_alpns,
                    selected_alpns=selected_alpns)


@app.route('/pcap', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        # if user does not select file, browser also
        # submit a empty part without filename
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            fullpath = os.path.join(UPLOAD_FOLDER, filename)
            file.save(fullpath)

            print('Ok to read "%s"?' % (fullpath))
            results = parsepcap.parse_pcap(fullpath)
            out = []
            for n, sni, fid in results:
                out.append({'n': n, 'sni': sni, 'hid': struct.pack('!q', fid).hex()})
            
            # remove file
            os.remove(fullpath)

            return render_template('pcap-results.html', results=out)
    return render_template('pcap.html')

@app.route('/norm_fp', methods=['GET'])
def norm_fp():
    return render_template('norm_fp.html')

@app.route('/labels')
def labels():
    global db_conn_pool
    with db_conn_pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute('''SELECT lid, label from labels;''')
