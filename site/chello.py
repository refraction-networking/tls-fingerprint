from flask import *
from tlsutil import *
import struct
from flask_caching import Cache
#from diff import myers_diff
import diff
import time
import random
from prod import db
from psycopg2 import sql
from werkzeug.utils import secure_filename
from tools import parsepcap
import os
import pickle
import math



UPLOAD_FOLDER = '/tmp/'
ALLOWED_EXTENSIONS = set(['pcap', 'pcapng'])

application = app = Flask(__name__)
cache = Cache(app, config={'CACHE_TYPE': 'filesystem', 'CACHE_DIR': '/tmp'})
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


def allowed_file(filename):
    return '.' in filename and \
            filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS



def hid(nid):
    return struct.pack('!q', nid).encode('hex')

def get_db():
    if not hasattr(g, 'psql_db'):
        g.psql_db = db.get_conn_cur()
    return g.psql_db


@app.route('/')
def index():
    return render_template('index.html')

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

import utls_support

#@cache.cached(key_prefix="total_seen13", timeout=3*3600)
def get_total_seen():
    db = get_db()
    db.cur.execute('''select sum(seen) from mv_ranked_fingerprints''')
    rows = db.cur.fetchall()
    return int(rows[0][0])

#@cache.cached(key_prefix="total_seen_week13", timeout=3*3600)
def get_total_seen_week():
    db = get_db()
    db.cur.execute('''select sum(seen) from mv_ranked_fingerprints_week''')
    rows = db.cur.fetchall()
    if rows is None or rows[0] is None or rows[0][0] is None:
        return 1
    return int(rows[0][0])



#@cache.cached(key_prefix="total_fps13", timeout=3*3600)
def get_total_fps():
    db = get_db()
    db.cur.execute('''select count(*) from mv_ranked_fingerprints''')
    rows = db.cur.fetchall()
    return int(rows[0][0])

def get_labels_for_fp(nid):
    db = get_db()
    db.cur.execute('select labels.lid, label from fingerprint_labels left join labels on fingerprint_labels.lid=labels.lid where fid=%s', [nid])
    out = []
    for row in db.cur.fetchall():
        out.append({'lid': row[0], 'name': row[1]})
    return out


# The list of alpns (these are a list of strings: ["h2", "http/1.1", ...])
def parse_alpns(alpn_str):
    alpns = []
    if alpn_str is not None and len(alpn_str) > 2:
        l, = struct.unpack('!H', alpn_str[0:2])
        idx = 2
        while idx < l:
            n, = struct.unpack('!B', alpn_str[idx])
            idx += 1
            alpns.append(repr(alpn_str[idx:idx+n])[1:-1])
            idx += n
    return alpns


def get_top_fps():
    db = get_db()
    # Get total...
    total = get_total_seen_week()

    #db.cur.execute('''select id, n, r from
    #    (select id, sum(count) as n, rank() over(order by sum(count) desc) as r, max(t) from
    #    (select id, count, timestamp with time zone 'epoch' + unixtime * INTERVAL '1 second' as t from measurements) as i
    #    where age(now(), t) > '2 hour' group by id order by n desc) as j LIMIT 20;''')
    #db.cur.execute('''select id, seen, rank from mv_ranked_fingerprints_week limit 20''')
    db.cur.execute('''select id, min(cluster_rank) as cluster_num, min(seen) as seen, min(rank) as rank
            from mv_ranked_fingerprints_week left join cluster_edges
                on mv_ranked_fingerprints_week.id=cluster_edges.source
            group by id order by seen desc limit 20;''')
    rows = db.cur.fetchall()
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


@app.route('/top/fingerprints')
#@cache.cached(key_prefix="top1", timeout=3*3600)
def top_fingerprints():
    # Top cipher suite
    #  select count(id), sum(n) from (select cs.id as id, COALESCE(m.n,0) as n from 
    #  (select id, cipher_suites from fingerprints where position('\xc02f' in cipher_suites)!=0)
    #  as cs left join (select id, sum(count) as n from measurements group by id order by n desc) as m on cs.id=m.id) as csm;
    top_ids = get_top_fps()
    top_ciphers = []

    return render_template('top-fingerprints.html', top_ids=top_ids, top_ciphers=top_ciphers)



@app.route('/top-unchosen-ciphers/')
def top_unchosen():
    db = get_db()
    total = get_total_seen()


    db.cur.execute('select distinct cipher_suite from sfingerprints;')
    selected_ciphers = set()
    for row in db.cur.fetchall():
        cs = row[0]
        if cs < 0:
            cs += 65536     # HACK to int16 -> uint16
        selected_ciphers.add(cs)

    #db.cur.execute('select sum(count) from measurements')
    #rows = db.cur.fetchall()
    #total_measurements = rows[0][0]

    db.cur.execute('''select * from
        (select count(*), sum(seen), cipher_suites
            from mv_ranked_fingerprints left join fingerprints
            on mv_ranked_fingerprints.id=fingerprints.id
            group by cipher_suites order by sum(seen) desc)
        as q
        where sum>1;''')

    #db.cur.execute('''select count(id), cipher_suites, COALESCE(sum(n),0) as n from
    #    (select fingerprints.id, cipher_suites, m.n from fingerprints
    #        left join
    #    (select id, sum(count) as n from measurements group by id order by n desc) as m
    #        on fingerprints.id=m.id) as fpm
    #    group by cipher_suites order by n desc;''')
    #rows = db.cur.fetchall()
    top_cs = {}  # cs => (fps, seen)
    for row in db.cur.fetchall():

        num_fps, seen, ciphers, = row
        for cs in bytea_to_u16s(ciphers):
            if cs in selected_ciphers:
                # Skip if it was ever selected
                continue
            if cs not in top_cs:
                top_cs[cs] = (0, 0)
            n, s = top_cs[cs]
            n += num_fps
            s += seen
            top_cs[cs] = (n, s)

    top_ciphers = []
    i = 0
    for cs, (n, s) in sorted(top_cs.iteritems(), key=lambda (k,v): v[1], reverse=True)[:20]:
        #cs, (n, s) = top_cs_combined[i]
        c = {}
        i += 1
        c['rank'] = i
        c['name'] = 'UNKNOWN'
        if cs in cipher_dict:
            c['name'] = cipher_dict[cs]
        c['id'] = cs
        c['fingerprints'] = n
        c['seen'] = s
        c['seen_f'] = 100.0*float(s)/total
        top_ciphers.append(c)

    return render_template('unchosen-ciphers.html', top_ciphers=top_ciphers)



@app.route('/top-ciphers/')
#@cache.cached(key_prefix="top-cipher", timeout=3*3600)
def top_ciphers():
    # total measurements
    db = get_db()
    total = get_total_seen()


    #db.cur.execute('select sum(count) from measurements')
    #rows = db.cur.fetchall()
    #total_measurements = rows[0][0]

    db.cur.execute('''select * from
        (select count(*), sum(seen), cipher_suites
            from mv_ranked_fingerprints left join fingerprints
            on mv_ranked_fingerprints.id=fingerprints.id
            group by cipher_suites order by sum(seen) desc)
        as q
        where sum>1;''')

    #db.cur.execute('''select count(id), cipher_suites, COALESCE(sum(n),0) as n from
    #    (select fingerprints.id, cipher_suites, m.n from fingerprints
    #        left join
    #    (select id, sum(count) as n from measurements group by id order by n desc) as m
    #        on fingerprints.id=m.id) as fpm
    #    group by cipher_suites order by n desc;''')
    #rows = db.cur.fetchall()
    top_cs = {}
    for row in db.cur.fetchall():

        num_fps, seen, ciphers, = row
        for cs in bytea_to_u16s(ciphers):
            if cs not in top_cs:
                top_cs[cs] = (0, 0)
            n, s = top_cs[cs]
            n += num_fps
            s += seen
            top_cs[cs] = (n, s)

    #top_cs_combined = 

    top_ciphers = []
    i = 0
    for cs, (n, s) in sorted(top_cs.iteritems(), key=lambda (k,v): v[1], reverse=True)[:20]:
        #cs, (n, s) = top_cs_combined[i]
        c = {}
        i += 1
        c['rank'] = i
        c['name'] = 'UNKNOWN'
        if cs in cipher_dict:
            c['name'] = cipher_dict[cs]
        c['id'] = cs
        c['fingerprints'] = n
        c['seen'] = s
        c['seen_f'] = 100.0*float(s)/total
        top_ciphers.append(c)

    # Top extensions/curves?


    top_ids = []
    return render_template('top-fingerprints.html', top_ids=top_ids, top_ciphers=top_ciphers, cipher_title='Top Cipher Suites')


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


#def levenshtein(s, t):
#    ''' From Wikipedia article; Iterative with two matrix rows. '''
#    if s == t: return 0
#    elif len(s) == 0: return len(t)
#    elif len(t) == 0: return len(s)
#    v0 = [None] * (len(t) + 1)
#    v1 = [None] * (len(t) + 1)
#    for i in range(len(v0)):
#        v0[i] = i
#    for i in range(len(s)):
#        v1[0] = i + 1
#        for j in range(len(t)):
#            cost = 0 if s[i] == t[j] else 1
#            v1[j + 1] = min(v1[j] + 1, v0[j + 1] + 1, v0[j] + cost)
#        for j in range(len(v0)):
#            v0[j] = v1[j]
#    return v1[len(t)]

class TLSFingerprint(object):
    def __init__(self, nid, tls_version, ch_version, cipher_suites, comp_methods, extensions,\
                curves, pt_fmts, sig_algs, alpn,\
                key_share, psk_key_exchange_modes, supported_versions, cert_compression_algs,\
                record_size_limit):
        self.nid = int(nid)
        self.tls_version = tls_version
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

    # String version of tls version
    def get_tls_version(self):
        return tls_ver_to_str(self.tls_version)

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

    def get_useragents(self):
        #from prod import db
        db = get_db()
        #db.conn.rollback()
        db.cur.execute("SELECT count(*) as d, useragent from useragents where id=%s group by useragent order by d desc", [int(self.nid)])
        rows = db.cur.fetchall()
        useragents = [row[1] for row in rows]
        return useragents

    def get_rank(self):
        db = get_db()
        #db.cur.execute('''SELECT id, n, r FROM
        #    (SELECT id, SUM(count) as n, RANK() OVER(ORDER BY SUM(count) DESC) as r, MAX(t) FROM
        #    (SELECT id, count, TIMESTAMP WITH TIME ZONE 'epoch' + unixtime * INTERVAL '1 second' as t FROM measurements) as ts
        #    where age(now(), t) > '2 hour' group by id order by n desc) as j where id=%s''', [int(self.nid)])
        db.cur.execute('''SELECT * FROM mv_ranked_fingerprints where id=%s''', [int(self.nid)])
        rows = db.cur.fetchall()
        self.seen = 0
        self.rank = -1
        self.frac_seen = 0.0

        if len(rows) > 0:
            self.seen = rows[0][1]
            self.rank = rows[0][2]

        db.cur.execute('''SELECT * FROM mv_ranked_fingerprints_week where id=%s''', [int(self.nid)])

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

    def get_lev_dist(self, other):

        return levenshtein(bytea_to_u16s(self.extensions), bytea_to_u16s(other.extensions)) + \
        levenshtein(bytea_to_u16s(self.cipher_suites), bytea_to_u16s(other.cipher_suites)) + \
        levenshtein(bytea_to_u16s(self.curves), bytea_to_u16s(other.curves)) + \
        levenshtein(bytea_to_u8s(self.comp_methods), bytea_to_u8s(other.comp_methods)) + \
        levenshtein(self.get_alpns(), other.get_alpns()) + \
        levenshtein(self.get_sig_algs(), other.get_sig_algs())

    def get_related(self, fetch_labels=False):
        #from prod import db
        db = get_db()
        #db.conn.rollback()

        total_seen = get_total_seen()
        db.cur.execute('''select * from (select id, seen,
        abs((select record_tls_version from fingerprints where id=%s) - record_tls_version) +
        abs((select ch_tls_version from fingerprints where id=%s) - ch_tls_version) +
        u16_lev((select cipher_suites from fingerprints where id=%s), cipher_suites) +
        u8_lev((select compression_methods from fingerprints where id=%s), compression_methods) +
        u16_lev((select extensions from fingerprints where id=%s), extensions) +
        u16_lev((select named_groups from fingerprints where id=%s), named_groups) +
        u8_lev_skiphdr((select ec_point_fmt from fingerprints where id=%s), ec_point_fmt) +
        u16_lev_skiphdr((select sig_algs from fingerprints where id=%s), sig_algs) +
        alpn_lev((select alpn from fingerprints where id=%s), alpn) +
            u16_lev((select key_share from fingerprints where id=%s), key_share) +
            u8_lev((select psk_key_exchange_modes from fingerprints where id=%s),
                   psk_key_exchange_modes) +
            u16_lev((select supported_versions from fingerprints where id=%s), supported_versions) +
            u16_lev_skipu8hdr((select cert_compression_algs from fingerprints where id=%s),
                    cert_compression_algs) +
            u16_lev((select record_size_limit from fingerprints where id=%s), record_size_limit)
        as lev from (select fingerprints.*, seen from mv_ranked_fingerprints_week left join fingerprints on mv_ranked_fingerprints_week.id=fingerprints.id where seen > 1000) as a order by lev) as q where lev < 10''', \
                    [self.nid]*14)

        rows = db.cur.fetchall()
        related = []
        for row in rows:
            c_id, c_seen, lev_dist = row
            if c_seen > 10000 and lev_dist < 8 and c_id != self.nid:
                labels = []
                if fetch_labels:
                    labels = get_labels_for_fp(c_id)
                related.append({'id':   struct.pack('!q', c_id).encode('hex'),
                          'lev':  lev_dist,
                          'seen': c_seen,
                          'labels': labels,
                          'frac': 100*float(c_seen)/total_seen})
        return related


    def get_labels(self):
        return get_labels_for_fp(self.nid)

    def generate_utls_code(self):
        # type: () -> (str, str, str)
        prefix = '''// import tls "github.com/refraction-networking/utls"
tcpConn, err := net.Dial("tcp", "tlsfingerprint.io:443")
if err != nil {
\tfmt.Printf("net.Dial() failed: %+v\\n", err)
\treturn
}

config := tls.Config{ServerName: "tlsfingerprint.io"}'''

        suffix = '''n, err = tlsConn.Write([]byte("Hello, World!"))
// or tlsConn.Handshake() for better control
'''
        # TODO: add tls versions
        getSessionId = "nil" # TODO: sha256.Sum256 if Chrome
        code = '''tlsConn := tls.UClient(tcpConn, &tlsConfig, tls.HelloCustom)
clientHelloSpec := tls.ClientHelloSpec {{
\tCipherSuites: []uint16{{
{}\t}},
\tCompressionMethods: []byte{{
{}\t}},
\tExtensions: []tls.TLSExtension{{
{}\t}},
}}
tlsConn.ApplyPreset(&clientHelloSpec)
        '''.format(utls_support.get_ciphers_str(self.cipher_suites),
                   utls_support.get_compressions_str(self.comp_methods),
                   utls_support.get_extensions_str(self.extensions, self.get_alpns(), self.sig_algs,
                                                   self.curves, self.pt_fmts,
                                                   self.supported_versions, self.psk_key_exchange_modes, self.key_share,
                                                   self.cert_compression_algs, self.record_size_limit),
        )
        return prefix, code, suffix


def lookup_fingerprint(fid):
    db = get_db()
    db.cur.execute("SELECT * FROM fingerprints WHERE id=%s", [int(fid)])
    rows = db.cur.fetchall()
    if len(rows) == 0:
        return None
    #fid_hex = struct.pack('!q', int(fid)).encode('hex')

    _, tls_ver, ch_ver, cipher_suites, comp_methods, exts, curves, pt_fmt, sig_algs, alpn, \
    key_share, psk_kex_modes, supported_versions, cert_comp_algs, record_size_limit = rows[0]

    return TLSFingerprint(fid, tls_ver, ch_ver, cipher_suites, comp_methods, exts, curves, \
            pt_fmt, sig_algs, alpn,\
            key_share, psk_kex_modes, supported_versions, cert_comp_algs, record_size_limit)

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
    fid1, = struct.unpack('!q', hid1.decode('hex'))
    fid2, = struct.unpack('!q', hid2.decode('hex'))

    fp1 = lookup_fingerprint(fid1)
    fp2 = lookup_fingerprint(fid2)

    if fp1 is None:
        return 'Not found: %s' % (struct.pack('!q', fid1).encode('hex'))
    if fp2 is None:
        return 'Not found: %s' % (struct.pack('!q', fid2).encode('hex'))

    ciphers_diff = get_sn_diff(fp1.get_ciphers(), fp2.get_ciphers())
    comps_diff   = get_sn_diff(fp1.get_comp_methods(), fp2.get_comp_methods())
    curves_diff  = get_sn_diff(fp1.get_curves(), fp2.get_curves())
    exts_diff    = get_sn_diff(fp1.get_extensions(), fp2.get_extensions())
    pt_fmt_diff  = get_sn_diff(fp1.get_pt_fmts(), fp2.get_pt_fmts())
    sigs_diff    = get_s_diff(fp1.get_sig_algs(), fp2.get_sig_algs())
    alpn_diff    = get_s_diff(fp1.get_alpns(), fp2.get_alpns())
    key_share_diff              = get_sn_diff(fp1.get_key_share(), fp2.get_key_share())
    psk_key_exchange_modes_diff = get_sn_diff(fp1.get_psk_key_exchange_modes(),
                                              fp2.get_psk_key_exchange_modes())
    supported_versions_diff     = get_sn_diff(fp1.get_supported_versions(), fp2.get_supported_versions())
    cert_compression_algs_diff  = get_sn_diff(fp1.get_cert_compression_algs(),
                                              fp2.get_cert_compression_algs())
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
        tls_ver1=fp1.get_tls_version(), tls_ver2=fp2.get_tls_version(), \
        ch_ver1=fp1.get_ch_version(), ch_ver2=fp2.get_ch_version(), \
        ciphers=fp1.get_ciphers(), ciphers_diff=ciphers_diff, \
        comps=fp1.get_comp_methods(), comps_diff=comps_diff, \
        curves=fp1.get_curves(), curves_diff=curves_diff, \
        extensions=fp1.get_extensions(), extensions_diff=exts_diff, \
        sig_algs=fp1.get_sig_algs(), sigs_diff=sigs_diff, \
        pt_fmts=fp1.get_pt_fmts(), pt_fmts_diff=pt_fmt_diff, \
        alpns=fp1.get_alpns(), alpn_diff=alpn_diff, \
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
    db = get_db()
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

    db.cur.execute(query, (bytea,))
    rows = db.cur.fetchall()
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
    db.cur.execute(query2, (bytea,))
    rows = db.cur.fetchall()
    num_seen, seen_total, = rows[0]

    #collected_ext_set = set([0x000a, 0x000b, 0x000d, 0x0010, 43, 45, 51, 0x001b, 0x001c])
    #if tbl == 'extension' and id_n in collected_ext_set:

    return render_template('find.html',
            fingerprints=fingerprints, this_seen_total=seen_total, num_seen=num_seen,
            total_seen=total_seen,
            id_str=id_str, id_n=id_n, tbl=tbl, thing=thing, comparator=comparator)

@app.route('/cluster.json/id/<hex_id>')
def cluster_json(hex_id):
    nid, = struct.unpack('!q', hex_id.decode('hex'))
    db = get_db()

    # Get all the edges
    db.cur.execute('select * from cluster_edges where cluster_rank=(select cluster_rank\
            from cluster_edges where source=%s limit 1);', [int(nid)])

    edges = []
    cluster_rank = None
    seen_nodes = set()
    for row in db.cur.fetchall():
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
    db.cur.execute('select source, min(seen) as seen from cluster_edges\
            left join mv_ranked_fingerprints_week on\
                cluster_edges.source=mv_ranked_fingerprints_week.id\
            where cluster_rank=%s group by source order by seen desc;', [int(cluster_rank)])
    nodes = []
    avail_nodes = set()
    for row in db.cur.fetchall():
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

def get_cluster_metadata(nid):
    db = get_db()
    db.cur.execute('''select count(*), sum(seen), min(cr) from
        (select source, min(seen) as seen, min(cluster_rank) as cr from
        cluster_edges left join mv_ranked_fingerprints_week
            on cluster_edges.source=mv_ranked_fingerprints_week.id
        where cluster_rank=
            (select cluster_rank from cluster_edges where source=%s limit 1)
        group by source) as q''', [int(nid)])

    rows = db.cur.fetchall()
    num_fps, cluster_seen, cluster_rank = rows[0]
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
    nid, = struct.unpack('!q', hid.decode('hex'))
    db = get_db()

    total_seen = get_total_seen_week()

    num_fps, cluster_seen, cluster_rank = get_cluster_metadata(nid)
    if cluster_seen is None:
        return 'Not found in any clusters (possibly not in a large enough cluster)'


    db.cur.execute('select distinct useragent from\
            (select distinct source from cluster_edges where cluster_rank=\
                (select cluster_rank from cluster_edges where source=%s limit 1)) as q\
                left join useragents on q.source=useragents.id;', [int(nid)])

    user_agents = sorted([r[0] for r in db.cur.fetchall() if r[0] is not None])

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
    db = get_db()

    db.cur.execute('''select cr as cluster_rank, count(*) as num_fps, coalesce(sum(seen),0) as seen,
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
    for row in db.cur.fetchall():
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
    nid, = struct.unpack('!q', hid.decode('hex'))
    db = get_db()

    db.cur.execute('''SELECT * from mv_ranked_fingerprints where id=%s''', [int(nid)])
    rows = db.cur.fetchall()
    if len(rows) == 0:
        return 'Not found'

    _, seen, rank = rows[0]
    fp = lookup_fingerprint(nid)

    diffs = []


    nid = int(nid)
    # TODO: alpn? ec_pt_fmts?
    db.cur.execute('''select * from (select fingerprints.id, seen,
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
    rows = db.cur.fetchall()
    for row in rows:
        c_id, c_seen, lev_dist = row

        #c_fp = lookup_fingerprint(c_id)

        #d = fp.get_lev_dist(c_fp)
        diffs.append({'lev':lev_dist, 'id':struct.pack('!q', c_id).encode('hex')})


    diffs = sorted(diffs, key=lambda x: x['lev'])
    return render_template('close.html', diffs=diffs, id=hid)

# Assumes data is an array like [[t0, v0], [t1, v1], [t2, v2] ...]
# and returns a similarly-shaped array, but window-averaged
def smooth_data(data, win=24):
    return zip([r[0] for r in data[win:]],
                [sum([r[1] for r in data[i:i+win]])/float(win) for i in xrange(len(data)-win+1)])


@app.route('/measurements/<hid>')
def measurements_hex(hid):
    nid, = struct.unpack('!q', hid.decode('hex'))
    db = get_db()

    # Build graph of measurements
    db.cur.execute('select unixtime, count from measurements where id=%s order by unixtime', [int(nid)])
    rows = db.cur.fetchall()
    return render_template('measurements.csv', data=rows)


@app.route('/data/norm/<hid>')
def norm_measurements_hex(hid):
    nid, = struct.unpack('!q', hid.decode('hex'))
    db = get_db()


    db.cur.execute('select mv_measurements_total.unixtime, 100*cast(COALESCE(count,0) as float) / cast(total as float) from mv_measurements_total left join (select * from measurements where id=%s) as m on mv_measurements_total.unixtime=m.unixtime order by unixtime', [int(nid)])
    rows = db.cur.fetchall()

    # Take 24-hour average (assumes each row is 1 hour)
    win = 24
    data = smooth_data(rows)
    return render_template('measurements.csv', data=data)

@app.route('/data/browsers')
def browsers_data():
    db = get_db()

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
        db.cur.execute('''SELECT mv_measurements_total.unixtime,
                                 100*cast(COALESCE(sum(count),0) AS float) / cast(min(total) AS float)
                        FROM mv_measurements_total LEFT JOIN
                        (SELECT * FROM measurements WHERE id IN %s) AS m
                        ON mv_measurements_total.unixtime=m.unixtime
                        GROUP BY mv_measurements_total.unixtime ORDER BY unixtime''', (tuple(ids),))

        rows = db.cur.fetchall()
        if len(dates) == 0:
            dates = [r[0] for r in rows[win:]]
        browser_data[browser] = [sum([a[1] for a in rows[i:i+win]])/float(win) for i in xrange(len(rows)-win+1)]


    browser_keys = ['iOS 10', 'iOS 11', 'Firefox 55-57', 'Chrome 58-63', 'Chrome 64'] # ordered how we want...
    # flatten/transpose data for render
    hdr_row = ['date']
    hdr_row += browser_keys
    data = [hdr_row]
    for i in xrange(len(dates)):
        row = [dates[i]]
        for browser in browser_keys:
            if len(browser_data[browser]) < len(dates):
                return 'Ok dunno what happened: %d != %d, %s => %s' % (len(browser_data[browser]), len(dates), browser, browser_data)
            row.append(browser_data[browser][i])
        data.append(row)

    return render_template('stacked.csv', data=data)



@app.route('/data/versions')
def version_data():
    db = get_db()

    versions = {768: 'ssl3.0',
                769: 'tls1.0',
                770: 'tls1.1',
                771: 'tls1.2',}


    db.cur.execute('''select record_tls_version, ch_tls_version, mv_version_times.unixtime,
                    100*cast(sum as float) / cast(total as float) as pct
                    from mv_version_times left join mv_measurements_total
                    on mv_version_times.unixtime=mv_measurements_total.unixtime;''')
    rows = db.cur.fetchall()
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
        ver_data_smooth[ver] = [sum([a[1][ver] for a in ver_data_items[i:i+win] if ver in a[1]])/float(win) for i in xrange(len(ver_data_items)-win+1)]

    hdr_row = ['date']
    hdr_row += ver_keys
    data = [hdr_row]
    for i in xrange(len(dates)):
        row = [dates[i]]
        for ver in ver_keys:
            row.append(ver_data_smooth[ver][i])
        data.append(row)

    return render_template('stacked.csv', data=data)




@app.route('/data/generic/<thing>')
def generic_data(thing):
    db = get_db()
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
        db.cur.execute(query)
        rows = db.cur.fetchall()
        return render_template(template, data=rows)


@app.route('/data/find/<tbl>/<hid>')
def param_generic_data(tbl, hid):
    # TODO TK

    db = get_db()

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

    db.cur.execute(query, [bytea])
    rows = db.cur.fetchall()
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
    db = get_db()
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

    db.cur.execute('''SELECT cipher_suites, count(*) as fps, sum(seen) as seen FROM mv_ranked_fingerprints_week
        LEFT JOIN fingerprints ON mv_ranked_fingerprints_week.id=fingerprints.id
        WHERE seen > 1
        GROUP BY cipher_suites ORDER BY seen DESC;''')
    for row in db.cur.fetchall():
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
    db = get_db()
    db.cur.execute('''SELECT sig_algs, count(*) as fps, sum(seen) as seen
            FROM mv_ranked_fingerprints_week
            LEFT JOIN fingerprints ON mv_ranked_fingerprints_week.id=fingerprints.id
            GROUP BY sig_algs ORDER BY seen DESC;''')

    totals = {} # {sig_alg} => (fps, seen)

    tot_fps = 0
    tot_seen = 0
    for row in db.cur.fetchall():
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


    return render_template('sig-algs.html',
            sig_algs=out, tot_fps=float(tot_fps), tot_seen=float(tot_seen))



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

@app.route('/id/<fid>')
def fingerprint_hex(fid):
    fid, = struct.unpack('!q', fid.decode('hex'))
    return fingerprint(fid)

@app.route('/nid/<fid>')
def fingerprint(fid):
    db = get_db()

    times = [time.time()]
    f = lookup_fingerprint(int(fid))    # 82 ms
    if f is None:
        return 'Not found'
    fid_hex = struct.pack('!q', int(fid)).encode('hex')

    times.append(time.time())
    rank, seen, frac_seen, rank_wk, seen_wk, frac_seen_wk = f.get_rank()     # 250 ms, 130 ms with caching of total_seen()
    times.append(time.time())

    if seen < 100:
        frac_seen = 0.00
    seen = format_seen(seen)
    seen_wk = format_seen(seen_wk)

    db.cur.execute("SELECT count(*) from fingerprints") # 48 ms
    rows = db.cur.fetchall()
    uniq = rows[0][0]

    db.cur.execute("SELECT count(*) from mv_ranked_fingerprints_week")
    rows = db.cur.fetchall()
    uniq_wk = rows[0][0]

    times.append(time.time())
    tls_ver = f.get_tls_version()  #
    times.append(time.time())
    ch_ver = f.get_ch_version()
    times.append(time.time())
    ciphers = f.get_ciphers()
    times.append(time.time())
    comps = f.get_comp_methods()
    times.append(time.time())
    exts = f.get_extensions()
    times.append(time.time())
    alpns = f.get_alpns()
    times.append(time.time())
    curves = f.get_curves()
    times.append(time.time())
    sig_algs = f.get_sig_algs()
    times.append(time.time())
    pt_fmts = f.get_pt_fmts()
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
    cert_compression_algs = f.get_cert_compression_algs()
    record_size_limit = f.get_record_size_limit()

    labels = f.get_labels()

    ext_str = f.get_hex_extensions_str()
    curves_str = f.get_hex_curves_str()
    version_str = f.get_hex_supported_versions_str()
    sigalgs_str = f.get_hex_sigalgs_str()

    times = [times[i]-times[i-1] for i in xrange(1, len(times))]

    utls_code_prefix, utls_code_body_unescaped, utls_code_suffix = f.generate_utls_code()

    # html escape utls_code_body first, then replace special strings
    # to highlight unsupported things with darkred
    utls_code_body = str(escape(utls_code_body_unescaped))
    utls_code_body_bck = str(utls_code_body)
    utls_code_body = utls_code_body.replace(utls_support.unknown_start, '<span style="color: darkred;">')
    utls_code_body = utls_code_body.replace(utls_support.unknown_end, '</span>')
    if utls_code_body != utls_code_body_bck:
        utls_code_body = '// This fingerprint includes feature(s), not fully supported by TLS.\n' \
                         '// uTLS client with this fingerprint will only be able to to talk to servers,\n' \
                         '// that also do not support those features. \n' + \
                         utls_code_body

    cluster_fps, cluster_seen, cluster_rank = get_cluster_metadata(fid)
    cluster_pct = 100.0*frac_seen_wk
    if cluster_seen != None:
        cluster_pct = 100*float(cluster_seen)/get_total_seen_week()


    return render_template('id.html', id=fid_hex, tls_ver=tls_ver, \
                ch_ver=ch_ver, ciphers=ciphers, \
                comps=comps, extensions=exts, \
                alpns=alpns, curves=curves, sig_algs=sig_algs, \
                pt_fmts=pt_fmts, useragents=useragents, \
                seen=seen, rank=rank, frac=100.0*frac_seen, unique=uniq, nid=fid, \
                seen_wk=seen_wk, rank_wk=rank_wk, frac_wk=100.0*frac_seen_wk, unique_wk=uniq_wk, \
                ciphers_str=ciphers_str, ext_str=ext_str, curves_str=curves_str, version_str=version_str,
                sigalgs_str=sigalgs_str,
                related=related, labels=labels, times=times,
                utls_code_prefix=utls_code_prefix, utls_code_body=utls_code_body, \
                utls_code_suffix=utls_code_suffix,\
                key_share=key_share, psk_key_exchange_modes=psk_key_exchange_modes,
                supported_versions=supported_versions,cert_compression_algs=cert_compression_algs,\
                record_size_limit=record_size_limit,\
                cluster_fps=cluster_fps, cluster_seen=cluster_seen, cluster_rank=cluster_rank,\
                cluster_pct=cluster_pct)


#def application(env, start_response):
#    start_response('200 OK', [('Content-Type','text/html')])
#    return [b"Hello World"]


@app.route('/session-tickets')
def session_tickets():
    db = get_db()

    db.cur.execute('''select sum(seen), (select sum(seen) from mv_ranked_fingerprints_week) from
                fingerprints left join mv_ranked_fingerprints_week on fingerprints.id=mv_ranked_fingerprints_week.id where position('\\x0023' in extensions)%2=1;''')
    seen, tot_seen = db.cur.fetchall()[0]
    pct_tickets = 100*float(seen)/float(tot_seen)

    db.cur.execute('''select size, round((100*cast(sum(count) as decimal) / (select sum(count) from ticket_sizes)), 2) as c from ticket_sizes group by size order by c desc;''')

    data = []
    i = 1
    for row in db.cur.fetchall():
        size, pct_conns = row
        data.append({'rank': i, 'size': size, 'pct_conns': pct_conns})
        i += 1

    return render_template('tickets.html', data=data, pct_tickets=pct_tickets)


def get_generic_top(column_name, thing_dict, top_n=None, thing_iter=bytea_to_u16s):
    db = get_db()

    query = sql.SQL('''select fingerprints.id, fingerprints.{}, mv_ranked_fingerprints_week.seen
                    from mv_ranked_fingerprints_week left join fingerprints on mv_ranked_fingerprints_week.id=fingerprints.id
                    where seen > 10 order by seen desc;''')
    db.cur.execute(query.format(sql.Identifier(column_name)))

    things = {}
    tot_seen = 0
    tot_fps = 0
    for row in db.cur.fetchall():
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
    db = get_db()

    db.cur.execute('''select cipher_suite, count(distinct sid), count(distinct cid), cast(sum(count) as float) / (select sum(count) from smeasurements) as frac
        from sfingerprints left join smeasurements on sfingerprints.id=smeasurements.sid
        group by cipher_suite order by sum(count) desc;''')
    data = []
    for row in db.cur.fetchall():
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
    db = get_db()

    db.cur.execute('select record_tls_version, ch_tls_version, supported_versions, coalesce(sum(seen),0) from\
            fingerprints left join mv_ranked_fingerprints_week\
            on fingerprints.id=mv_ranked_fingerprints_week.id\
            group by record_tls_version, ch_tls_version, supported_versions order by coalesce desc;')

    versions = {}   # (min, max => seen
    max_versions = {}   # max => seen
    for row in db.cur.fetchall():
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
    total_cluster_fps, total_cluster_pct_seen, clusters = cluster_summary()

    return render_template('top-summary.html', top_versions=top_versions,
            top_exts=top_exts, top_groups=top_groups, top_ids=top_ids,
            top_ciphers=top_ciphers, clusters=clusters[:5])


@app.route('/server-ciphers')
def server_ciphers():

    return render_template('server-ciphers.html', data=get_top_selected_ciphers())


@app.route('/alpn')
def alpn():
    db = get_db()

    total_seen = get_total_seen()
    total_fps = get_total_fps()

    LIMIT_ROWS = 20

    db.cur.execute('''select count(*), coalesce(sum(seen), 0), alpn
                    from mv_ranked_fingerprints left join fingerprints
                    on fingerprints.id=mv_ranked_fingerprints.id
                    group by alpn order by coalesce(sum(seen),0) desc;''')

    client_alpns = []
    popular_alpns = {}   # 'alpn': (num_fps, seen)

    n = 0

    for row in db.cur.fetchall():
        num_fps, seen, alpn, = row
        try:
            alpn_list = parse_alpns(alpn)
        except IndexError:
            print 'Error parsing alpn: %s' % (''.join(['%02x' % ord(c) for c in alpn]))
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

    db.cur.execute('''select count(*), sum(count) from smeasurements''')
    total_fps, total_seen, = db.cur.fetchall()[0]

    db.cur.execute('''select count(*), sum(count), alpn
            from sfingerprints left join smeasurements
            on sfingerprints.id=smeasurements.sid
            group by alpn order by sum(count) desc''')

    selected_alpns = []
    for row in db.cur.fetchall():
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

            print 'Ok to read "%s"?' % (fullpath)
            results = parsepcap.parse_pcap(fullpath)
            out = []
            for n, sni, fid in results:
                out.append({'n': n, 'sni': sni, 'hid': struct.pack('!q', fid).encode('hex')})
            return render_template('pcap-results.html', results=out)
    return render_template('pcap.html')



@app.route('/labels')
def labels():
    db = get_db()

    db.cur.execute('''SELECT lid, label from labels;''')
