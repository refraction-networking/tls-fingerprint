from flask import Flask, render_template
from psycopg2 import sql
from prod import db


app = Flask(__name__)

def get_db():
    if not hasattr(g, 'psql_db'):
        g.psql_db = db.get_conn_cur()
    return g.psql_db


@app.route('/')
def index():
    return render_template('quic.html')


def get_top():
    db = get_db()
    # Get total...
    #total = get_total_seen_week()

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
    top_ids = get_top()

    return render_template('quic-top.html', top_ids=top_ids)

# TODO: 4 kinds of fingerprints:
# -fpid  (main ID, fingerprint ID) - combination of lower 3
# -qid   QUIC fingerprint. QUIC header-specific parts (version, SID/DID lengths, etc)
# -tlsid TLS Client Hello fingerprint (from inner Client Hello)
# -tpid  QUIC transport parameters - the types/values in the QUIC-specific Client Hello extension
@app.route('/id/<fid>') # hex
def fingerprint_hex(fid):
    fid, = struct.unpack('!q', fid.decode('hex'))
    return fingerprint(fid)

@app.route('/nid/<fid>') # decimal
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

    return render_template('quic-id.html', id=fid_hex, tls_ver=tls_ver, \
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


