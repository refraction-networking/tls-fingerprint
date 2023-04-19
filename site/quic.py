from flask import Flask, render_template, g
from psycopg2 import sql
from prod import db
from tlsutil import *
from fprints import *

app = Flask(__name__)

def get_db():
    if not hasattr(g, 'psql_db'):
        g.psql_db = db.get_conn_cur('quic_fp')
    return g.psql_db


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
    db.cur.execute('''select id, sum(count) as seen, rank() over(order by sum(count) desc) as rank from quic_measurements group by id limit 15''')
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

    db.cur.execute('''select id, sum(count) as seen, rank() over(order by sum(count) desc) as rank from tls_measurements_norm_ext group by id limit 15''')
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

#@cache.cached(key_prefix="top1", timeout=3*3600)
@app.route('/top')
def top_fingerprints():
    top_ids = get_top_quic()
    return render_template('quic-top.html', top_quic_ids=top_ids, top_tls_ids=top_tls())

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

    return render_template('quic-id.html', id=qid_hex, nid=qid, \
        seen=seen, rank=rank, unique=uniq, frac=100.0*frac_seen, \
        quic_version=quic.get_version(), sid_len=quic.sid_len, did_len=quic.did_len, \
        frames=quic.get_frames_str(), token_len=quic.token_len, pkt_num=quic.get_pkt_num())


@app.route('/tid/<tid>') # hex
def tls_fingerprint_hex(tid):
    tnid, = struct.unpack('!q', bytes.fromhex(tid))
    return tls_fingerprint(tnid)

@app.route('/tnid/<tnid>') # decimal
def tls_fingerprint(tnid):
    db = get_db()

    tls = lookup_tls(db, int(tnid))
    if tls is None:
        return 'Not found'

    db.cur.execute('SELECT count(*) from tls_fingerprints_norm_ext')
    uniq = int(db.cur.fetchall()[0][0])

    db.cur.execute('SELECT sum(count) from tls_measurements_norm_ext')
    total = int(db.cur.fetchall()[0][0])




# TODO: 4 kinds of fingerprints:
# -fpid  (main ID, fingerprint ID) - combination of lower 3
# -qid   QUIC fingerprint. QUIC header-specific parts (version, SID/DID lengths, etc)
# -tlsid TLS Client Hello fingerprint (from inner Client Hello)
# -tpid  QUIC transport parameters - the types/values in the QUIC-specific Client Hello extension
@app.route('/id/<fid>') # hex
def fingerprint_hex(fid):
    fid, = struct.unpack('!q', fid.decode('hex'))
    return fingerprint(fid)

'''
@app.route('/nid/<fid>') # decimal
def fingerprint(fid):
    db = get_db()

    times = [time.time()]
    # TODO: lookup all 4 fingerprints
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

    db.cur.execute("SELECT count(*) from fingerprints_norm_ext") # 48 ms
    rows = db.cur.fetchall()
    uniq = rows[0][0]

    db.cur.execute("SELECT count(*) from mv_ranked_fingerprints_norm_ext_week")
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

    return render_template('quic-id.html', id=fid_hex, nid=fid, \
        seen=seen, rank=rank, unique=uniq, frac=100.0*frac_seen, \
        quic_version=quic_version, sid_len=sid_len, did_len=did_len, \
        frames=frames, token_len=token_len, pkt_num=pkt_num, \
        max_idle_timeout=max_idle_timeout, max_udp_payload_size=max_udp_payload_size, \
        initial_max_data=initial_max_data, initial_max_stream_data_bidi_local, \
        initial_max_stream_data_bidi_remote=initial_max_stream_data_bidi_remote, \
        initial_max_streams_bidi=initial_max_streams_bidi, \
        initial_max_streams_uni=initial_max_streams_uni, \
        ack_delay_exponent=ack_delay_exponent, max_ack_delay=max_ack_delay, \
        disable_active_migration=disable_active_migration, \
        active_connection_id_limit=active_connection_id_limit, \
        ch_ver=ch_ver, ciphers=ciphers, \
        comps=comps, extensions=exts, \
        alpns=alpns, curves=curves, sig_algs=sig_algs, \
        pt_fmts=pt_fmts, useragents=useragents, \
        ciphers_str=ciphers_str, ext_str=ext_str, curves_str=curves_str, version_str=version_str,
        sigalgs_str=sigalgs_str,
        key_share=key_share, psk_key_exchange_modes=psk_key_exchange_modes,
        supported_versions=supported_versions,cert_compression_algs=cert_compression_algs,\
        record_size_limit=record_size_limit,times=times)
        #times=times)

'''

