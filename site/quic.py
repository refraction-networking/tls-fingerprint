from flask import Flask, render_template, g
from psycopg2 import sql
from prod import db
from tlsutil import *
from fprints import *
import diff


app = Flask(__name__)

def get_db():
    if not hasattr(g, 'psql_db'):
        g.psql_db = db.get_conn_cur('quic_fp')
    return g.psql_db

def format_seen(seen):
    if seen is None:
        return '0'
    seen = int(seen)
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

def get_total_seen(db):
    db.cur.execute('select sum(count) from super_measurements')
    return db.cur.fetchall()[0][0]

@app.route('/')
def index():
    return render_template('quic.html')

def hid(nid):
    return struct.pack('!q', nid).hex()

def get_top_quic():
    db = get_db()
    # Get total...
    #total = get_total_seen_week()
    db.cur.execute('''select sum(count) from quic_measurements''')
    rows = db.cur.fetchall()
    total = rows[0][0]

    #db.cur.execute('''select id, n, r from
    #    (select id, sum(count) as n, rank() over(order by sum(count) desc) as r, max(t) from
    #    (select id, count, timestamp with time zone 'epoch' + unixtime * INTERVAL '1 second' as t from measurements) as i
    #    where age(now(), t) > '2 hour' group by id order by n desc) as j LIMIT 20;''')
    #db.cur.execute('''select id, seen, rank from mv_ranked_fingerprints_week limit 20''')
    db.cur.execute('''select * from (select id, sum(count) as seen, rank() over(order by sum(count) desc) as rank from quic_measurements group by id limit 15) as a order by rank''')
    rows = db.cur.fetchall()
    top_ids = []
    for row in rows:
        nid, seen, rank = row
        nid = int(nid)
        top_ids.append({'qnid': nid,
                        'qid': hid(nid),
                        'count': seen,
                        'rank': rank,
                        'frac': 100.0*float(seen) / total})

    return top_ids


def top_tls():
    db = get_db()
    db.cur.execute('''select sum(count) from tls_measurements_norm_ext''')
    rows = db.cur.fetchall()
    total = rows[0][0]

    db.cur.execute('''select * from (select id, sum(count) as seen, rank() over(order by sum(count) desc) as rank from tls_measurements_norm_ext group by id limit 15) as a order by rank''')
    rows = db.cur.fetchall()
    top_ids = []
    for row in rows:
        nid, seen, rank = row
        nid = int(nid)
        top_ids.append({'tnid': nid,
            'tid': hid(nid),
            'count': seen,
            'rank': rank,
            'frac': 100.0*float(seen) / total})
    return top_ids

def top_super():
    db = get_db()
    db.cur.execute('''select sum(count) from super_measurements''')
    rows = db.cur.fetchall()
    total = int(rows[0][0])

    #db.cur.execute('''select * from (select a.id, seen, rank, quic_fp, tls_fp, qtp_fp from (select id, sum(count) as seen, rank() over(order by sum(count) desc) as rank from super_measurements group by id limit 15) as a left join super_fingerprints on a.id=super_fingerprints.id) as a order by rank''')
    db.cur.execute('select * from (select a.id, seen, rank, quic_fp, tls_fp, qtp_fp, name, observed from (select id, sum(count) as seen, rank() over(order by sum(count) desc) as rank from super_measurements group by id limit 15) as a left join super_fingerprints on a.id=super_fingerprints.id left join labels_inferred on super_fingerprints.id=labels_inferred.id) as a order by rank')
    rows = db.cur.fetchall()
    top_ids = []
    for row in rows:
        nid, seen, rank, qid, tid, tpid, name, observed = row
        nid = int(nid)
        lbl = ''
        if name is not None:
            lbl = name if observed else 'Likely %s' % name
        top_ids.append({'nid': nid,
            'id': hid(nid),
            'count': seen,
            'rank': rank,
            'quic_id': hid(qid),
            'tls_id': hid(tid),
            'qtp_id': hid(tpid),
            'name': lbl,
            'frac': 100.0*float(seen) / total})
    return top_ids

def top_labels():
    db = get_db()

    total_super = get_total_seen(db)

    #db.cur.execute('select name, count(distinct labels.id) as uniq_fps, sum(count) as seen from labels left join super_measurements on labels.id=super_measurements.id GROUP by labels.name order by seen desc')
    #    name     | uniq_fps |  seen
    #-------------+----------+---------
    # Chrome 113  |        5 | 7651724
    # Firefox 113 |       12 |  488298


    db.cur.execute('select name, sum(observed) as observ, count(distinct id) as uniq_fps, count(distinct quic_fp) as uniq_qui, count(distinct tls_fp) as uniq_tls, count(distinct qtp_fp) as uniq_qtp, sum(seen) as seen from (select labels_inferred.id, min(labels_inferred.name) as name, bool_and(labels_inferred.observed)::int as observed, min(super_fingerprints.quic_fp) as quic_fp, min(super_fingerprints.tls_fp) as tls_fp, min(super_fingerprints.qtp_fp) as qtp_fp, sum(count) as seen from labels_inferred left join super_fingerprints on labels_inferred.id=super_fingerprints.id left join super_measurements on labels_inferred.id=super_measurements.id group by labels_inferred.id) as a group by name order by seen desc;')
    #       name      | observ | uniq_fps | uniq_qui | uniq_tls | uniq_qtp |   seen   
    # ----------------+--------+----------+----------+----------+----------+----------
    # Chrome 113     |      5 |      787 |      232 |        2 |       32 | 10481866
    # Safari 16.5    |      2 |      138 |       32 |        2 |       12 |  6942895
    # Firefox 113    |     12 |      676 |      227 |        2 |        3 |  1205447
    # Edge 113       |      3 |      112 |       81 |        2 |        2 |   658429
    # quic-go 0.32.0 |      5 |       12 |       12 |        1 |        1 |       26
    # quic-go 0.34.0 |      5 |        9 |        9 |        1 |        1 |       19


    top_labels = []
    rank = 0
    for row in db.cur.fetchall():
        rank += 1
        name, observed, uniq_fps, uniq_quic, uniq_tls, uniq_qtp, seen = row
        top_labels.append({'rank': rank,
                           'name': name,
                           'observed': observed,
                           'seen': seen,
                           'frac': 100*float(seen)/total_super,
                           'uniq_fps': uniq_fps,
                           'uniq_quic': uniq_quic,
                           'uniq_tls': uniq_tls,
                           'uniq_qtp': uniq_qtp,
                          })



    db.cur.execute('select name, sum(observed) as observ, count(distinct id) as uniq_fps, count(distinct quic_fp) as uniq_qui, count(distinct tls_fp) as uniq_tls, count(distinct qtp_fp) as uniq_qtp, sum(seen) as seen from (select labels_inferred.id, min(labels_inferred.name) as name, bool_and(labels_inferred.observed)::int as observed, min(super_fingerprints.quic_fp) as quic_fp, min(super_fingerprints.tls_fp) as tls_fp, min(super_fingerprints.qtp_fp) as qtp_fp, sum(count) as seen from labels_inferred left join super_fingerprints on labels_inferred.id=super_fingerprints.id left join super_measurements on labels_inferred.id=super_measurements.id where observed group by labels_inferred.id) as a group by name order by seen desc;')
    for row in db.cur.fetchall():
        rank += 1
        name, observed, uniq_fps, uniq_quic, uniq_tls, uniq_qtp, seen = row
        top_labels.append({'rank': rank,
                           'name': 'Observed ' + name,
                           'observed': observed,
                           'seen': seen,
                           'frac': 100*float(seen)/total_super,
                           'uniq_fps': uniq_fps,
                           'uniq_quic': uniq_quic,
                           'uniq_tls': uniq_tls,
                           'uniq_qtp': uniq_qtp,
                          })

    return top_labels


#@cache.cached(key_prefix="top1", timeout=3*3600)
@app.route('/top')
def top_fingerprints():
    top_ids = get_top_quic()
    return render_template('quic-top.html', top_quic_ids=top_ids, top_tls_ids=top_tls(),
            top_super_ids=top_super(), top_labels=top_labels())

@app.route('/qid/<qhid>') # hex
def qid(qhid):
    qid, = struct.unpack('!q', bytes.fromhex(qhid))
    return qfp(qid)

@app.route('/qnid/<qid>') # decimal
def qfp(qid):
    db = get_db()
    qid_hex = struct.pack('!q', int(qid)).hex()

    quic = lookup_qfp(db, qid)
    if quic is None:
        return 'Not found'

    db.cur.execute('''select * from (select id, sum(count) as seen, rank() over(order by sum(count) desc) as rank from quic_measurements group by id) as a where id=%s''', [int(qid)])
    rows = db.cur.fetchall()
    _, seen, rank = rows[0]
    db.cur.execute('''select count(*), sum(seen) from (select id, sum(count) as seen, rank() over(order by sum(count) desc) as rank from quic_measurements group by id) as a;''')
    rows = db.cur.fetchall()
    uniq, tot_seen = rows[0]
    frac_seen = 0.0
    if tot_seen > 0:
        frac_seen = float(seen)/float(tot_seen)

    total_super = get_total_seen(db)

    db.cur.execute('select a.id, min(a.quic_fp), min(a.tls_fp), min(a.qtp_fp), sum(count) as seen, min(labels_inferred.name), bool_and(labels_inferred.observed) from (select * from super_fingerprints where quic_fp=%s) as a left join super_measurements on a.id=super_measurements.id left join labels_inferred on a.id=labels_inferred.id group by a.id order by seen desc;', [int(qid)])
    related_fps = []
    for row in db.cur.fetchall()[:15]:
        sid, quic_fp, tls_fp, qtp_fp, r_seen, name, observed = row
        lbl = ''
        if name is not None:
            lbl = name if observed else 'Likely %s' % name
        o = {'id': hid(sid),
             'quic_fp': hid(quic_fp),
             'tls_fp': hid(tls_fp),
             'qtp_fp': hid(qtp_fp),
             'seen': r_seen,
             'name': lbl,
             'frac': 100.0*(r_seen / total_super),
            }
        related_fps.append(o)




    return render_template('quic-id.html', id=qid_hex, nid=qid, \
        seen=seen, rank=rank, unique=uniq, frac=100.0*frac_seen, \
        quic_version=quic.get_version(), sid_len=quic.sid_len, did_len=quic.did_len, \
        frames=quic.get_frames_str(), token_len=quic.token_len, pkt_num=quic.get_pkt_num(),
        related_fps=related_fps)


@app.route('/tid/<tid>') # hex
def tls_fingerprint_hex(tid):
    tnid, = struct.unpack('!q', bytes.fromhex(tid))
    return tls_fingerprint(tnid)

@app.route('/tnid/<tnid>') # decimal
def tls_fingerprint(tnid):
    tnid = int(tnid)
    db = get_db()

    tls = lookup_tls(db, int(tnid))
    if tls is None:
        return 'Not found'

    db.cur.execute('SELECT count(*) from tls_fingerprints_norm_ext')
    uniq = int(db.cur.fetchall()[0][0])

    db.cur.execute('select min(case when id=%s then rank end), sum(case when id=%s then seen end), sum(seen) from (select id, sum(count) as seen, rank() over(order by sum(count) desc) as rank from tls_measurements_norm_ext group by id) as a;', [int(tnid), int(tnid)])

    rank, seen, total = db.cur.fetchall()[0]

    #return 'Cipher suite str: %s, %s' % (type(tls.cipher_suites), bytes(tls.cipher_suites))
    total_super = get_total_seen(db)

    db.cur.execute('select a.id, min(a.quic_fp), min(a.tls_fp), min(a.qtp_fp), sum(count) as seen, min(labels_inferred.name), bool_and(labels_inferred.observed) from (select * from super_fingerprints where tls_fp=%s) as a left join super_measurements on a.id=super_measurements.id left join labels_inferred on a.id=labels_inferred.id group by a.id order by seen desc;', [int(tnid)])
    related_fps = []
    for row in db.cur.fetchall()[:15]:
        sid, quic_fp, tls_fp, qtp_fp, r_seen, name, observed = row
        if r_seen is None:
            r_seen = 0
        lbl = ''
        if name is not None:
            lbl = name if observed else 'Likely %s' % name
        o = {'id': hid(sid),
             'quic_fp': hid(quic_fp),
             'tls_fp': hid(tls_fp),
             'qtp_fp': hid(qtp_fp),
             'seen': r_seen,
             'name': lbl,
             'frac': 100.0*(r_seen / total_super),
            }
        related_fps.append(o)

    return render_template('quic-tls-id.html', id=hid(tnid), nid=tnid,
            seen=int(seen), rank=int(rank), unique=uniq, frac=100*float(seen)/int(total),
            ch_ver=tls.get_ch_version(),
            ciphers_str=tls.get_hex_cipher_suite_str(),
            ciphers=tls.get_ciphers(),
            comps=tls.get_comp_methods(),
            ext_str=tls.get_hex_extensions_str(),
            extensions=tls.get_extensions(),
            curves_str=tls.get_hex_curves_str(),
            curves=tls.get_curves(),
            sigalgs_str=tls.get_hex_sigalgs_str(),
            sig_algs=tls.get_sig_algs(),
            pt_fmts=tls.get_pt_fmts(),
            alpns=tls.get_alpns(),
            key_share=tls.get_key_share(),
            psk_key_exchange_modes=tls.get_psk_key_exchange_modes(),
            version_str=tls.get_hex_supported_versions_str(),
            supported_versions=tls.get_supported_versions(),
            cert_compression_algs=tls.get_cert_compression_algs(),
            record_size_limit=tls.get_record_size_limit(),
            related_fps=related_fps)


@app.route('/qtp/<qid>') # hex
def qtp_fingerprint_hex(qid):
    qtpid, = struct.unpack('!q', bytes.fromhex(qid))
    return qtp_fingerprint(qtpid)

@app.route('/qtpnid/<qtpid>') # decimal
def qtp_fingerprint(qtpid):
    db = get_db()

    qtp = lookup_qtp(db, int(qtpid))
    if qtp is None:
        return 'Not found'

    db.cur.execute('SELECT count(*) from qtp_fingerprints')
    uniq = int(db.cur.fetchall()[0][0])

    db.cur.execute('select min(case when id=%s then rank end), sum(case when id=%s then seen end), sum(seen) from (select id, sum(count) as seen, rank() over(order by sum(count) desc) as rank from qtp_measurements group by id) as a;', [int(qtpid), int(qtpid)])

    rank, seen, total = db.cur.fetchall()[0]

    #return 'Cipher suite str: %s, %s' % (type(tls.cipher_suites), bytes(tls.cipher_suites))
    total_super = get_total_seen(db)

    db.cur.execute('select a.id, min(a.quic_fp), min(a.tls_fp), min(a.qtp_fp), sum(count) as seen, min(labels_inferred.name), bool_and(labels_inferred.observed) from (select * from super_fingerprints where qtp_fp=%s) as a left join super_measurements on a.id=super_measurements.id left join labels_inferred on a.id=labels_inferred.id group by a.id order by seen desc;', [int(qtpid)])
    related_fps = []
    for row in db.cur.fetchall()[:15]:
        sid, quic_fp, tls_fp, qtp_fp, r_seen, name, observed = row
        lbl = ''
        if name is not None:
            lbl = name if observed else 'Likely %s' % name
        o = {'id': hid(sid),
             'quic_fp': hid(quic_fp),
             'tls_fp': hid(tls_fp),
             'qtp_fp': hid(qtp_fp),
             'seen': r_seen,
             'name': lbl,
             'frac': 100.0*(r_seen / total_super),
            }
        related_fps.append(o)

    return render_template('quic-qtp-id.html', id=hid(qtpid), nid=qtpid,
            seen=int(seen), rank=int(rank), unique=uniq, frac=100*float(seen)/int(total),
            qtp=qtp,
            related_fps=related_fps)
 

 

# TODO: 4 kinds of fingerprints:
# -fpid  (main ID, fingerprint ID) - combination of lower 3
# -qid   QUIC fingerprint. QUIC header-specific parts (version, SID/DID lengths, etc)
# -tlsid TLS Client Hello fingerprint (from inner Client Hello)
# -tpid  QUIC transport parameters - the types/values in the QUIC-specific Client Hello extension
@app.route('/id/<fid>') # hex
def fingerprint_hex(fid):
    fid, = struct.unpack('!q', bytes.fromhex(fid))
    return fingerprint(fid)

@app.route('/nid/<fid>') # decimal
def fingerprint(fid):
    db = get_db()

    # TODO: lookup all 4 fingerprints
    f = lookup_fingerprints(db, int(fid))
    if f is None:
        return 'Not found'
    fid_hex = hid(int(fid))

    rank, seen, frac_seen, total = f.get_rank(db) # sloooow...
    #rank_wk, seen_wk, frac_seen_wk = f.get_rank()     # 250 ms, 130 ms with caching of total_seen()

    if seen is None or seen < 100:
        frac_seen = 0.00
    seen = format_seen(seen)
    #seen_wk = format_seen(seen_wk)

    db.cur.execute("SELECT count(*) from super_fingerprints") # 48 ms
    rows = db.cur.fetchall()
    uniq = rows[0][0]

    #db.cur.execute("SELECT count(*) from mv_ranked_fingerprints_norm_ext_week")
    #rows = db.cur.fetchall()
    #uniq_wk = rows[0][0]

    tls = f.tls
    quic = f.quic
    qtp = f.qtp

    return render_template('quic-full-id.html', id=fid_hex, nid=fid,
        seen=seen, rank=rank, unique=uniq, frac=100.0*frac_seen,
        quic_fp=hid(quic.nid),
        quic_version=quic.get_version(), sid_len=quic.sid_len, did_len=quic.did_len,
        frames=quic.get_frames_str(), token_len=quic.token_len, pkt_num=quic.get_pkt_num(),
        tls_fp=hid(tls.nid),
            ch_ver=tls.get_ch_version(),
            ciphers_str=tls.get_hex_cipher_suite_str(),
            ciphers=tls.get_ciphers(),
            comps=tls.get_comp_methods(),
            ext_str=tls.get_hex_extensions_str(),
            extensions=tls.get_extensions(),
            curves_str=tls.get_hex_curves_str(),
            curves=tls.get_curves(),
            sigalgs_str=tls.get_hex_sigalgs_str(),
            sig_algs=tls.get_sig_algs(),
            pt_fmts=tls.get_pt_fmts(),
            alpns=tls.get_alpns(),
            key_share=tls.get_key_share(),
            psk_key_exchange_modes=tls.get_psk_key_exchange_modes(),
            version_str=tls.get_hex_supported_versions_str(),
            supported_versions=tls.get_supported_versions(),
            cert_compression_algs=tls.get_cert_compression_algs(),
            record_size_limit=tls.get_record_size_limit(),
        qtp_fp=hid(qtp.nid),
        max_idle_timeout=qtp.max_idle_timeout,
        max_udp_payload_size=qtp.max_udp_payload_size,
        initial_max_data=qtp.initial_max_data,
        initial_max_stream_data_bidi_local=qtp.initial_max_stream_data_bidi_local,
        initial_max_stream_data_bidi_remote=qtp.initial_max_stream_data_bidi_remote, \
        initial_max_stream_data_uni=qtp.initial_max_stream_data_uni, \
        initial_max_streams_bidi=qtp.initial_max_streams_bidi, \
        initial_max_streams_uni=qtp.initial_max_streams_uni, \
        ack_delay_exponent=qtp.ack_delay_exponent, max_ack_delay=qtp.max_ack_delay, \
        active_connection_id_limit=qtp.active_connection_id_limit,\
        qtp_params=qtp.get_param_ids())
        #times=times)
        #disable_active_migration=qtp.disable_active_migration, \

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



@app.route('/compare/<hid1>/<hid2>')
def compare(hid1, hid2):
    fid1, = struct.unpack('!q', bytes.fromhex(hid1))
    fid2, = struct.unpack('!q', bytes.fromhex(hid2))
    db = get_db()

    # TODO: lookup all 4 fingerprints
    fp1 = lookup_fingerprints(db, int(fid1))
    fp2 = lookup_fingerprints(db, int(fid2))
    if fp1 is None:
        return 'Not found: %s' % (hid1)
    if fp2 is None:
        return 'Not found: %s' % (hid2)

    

