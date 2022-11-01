from tlsutil import *


import pickle
from prod import db
import random
import time
db = db.get_conn_cur()


MAX_LEV_DIST = 10
fps = []     #list o fingerprints
groups = []  # list of set()s of fingerprints < LEV_DIST away from one another

dists = {}  # fp => { dist => set() of fingerprints $lev away) }
            # we DFS this to generate groups





db.cur.execute('select sum(seen) from mv_ranked_fingerprints')
rows = db.cur.fetchall()
total_seen = int(rows[0][0])




db.cur.execute('''select id from mv_ranked_fingerprints where seen > 1000''')
for row in db.cur.fetchall():
    fps.append(row[0])

i=0
for fp in fps:
    i += 1
    if (i % 100) == 0:
        print 'Importing #%d: %s...' % (i, fp)
    #total_seen = get_total_seen()
    db.cur.execute('''select * from (select id, seen,
        u16_lev((select cipher_suites from fingerprints where id=%s), cipher_suites) +
        u16_lev((select extensions from fingerprints where id=%s), extensions) +
        u16_lev((select eliptic_curves from fingerprints where id=%s), eliptic_curves) +
        u8_lev((select compression_methods from fingerprints where id=%s), compression_methods) +
        u16_lev_skiphdr((select sig_algs from fingerprints where id=%s), sig_algs) +
        abs((select record_tls_version from fingerprints where id=%s) - record_tls_version) +
        abs((select ch_tls_version from fingerprints where id=%s) - ch_tls_version)
        as lev from (select fingerprints.*, seen from mv_ranked_fingerprints left join fingerprints on mv_ranked_fingerprints.id=fingerprints.id where seen > 1000) as a order by lev) as q where lev < 10''', \
                    [fp]*7)

    rows = db.cur.fetchall()
    related = []

    dists[fp] = {}
    for row in rows:
        c_id, c_seen, lev_dist = row
        if c_seen > 1000 and lev_dist < MAX_LEV_DIST and c_id != fp:
            if lev_dist not in dists[fp]:
                dists[fp][lev_dist] = set()
            dists[fp][lev_dist].add(c_id)


print 'Done importing %d fingerprints' % len(dists)
print 'Writing to "lev-dists.data"...'
with open('lev-dists.data', 'w') as f:
    pickle.dump(dists, f, pickle.HIGHEST_PROTOCOL)
print 'Done'



