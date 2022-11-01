from tlsutil import *


import sys
sys.setrecursionlimit(10000)
import pickle
from prod import db
import random
import time
db = db.get_conn_cur()

LEV_DIST = 5
MAX_LEV_DIST = 10       # what we populate dists with
fps = []     #list o fingerprints
groups = []  # list of set()s of fingerprints < LEV_DIST away from one another

dists = {}  # fp => { dist => set() of fingerprints $lev away) }
            # we DFS this to generate groups


def load_fp_dists_from_db():
    dists = {}
    db.cur.execute('''select id from mv_ranked_fingerprints_week where seen > 1000''')
    for row in db.cur.fetchall():
        fps.append(row[0])

    i=0
    print 'Reading %d fingerprints from DB...' % (len(fps))
    for fp in fps:
        i += 1
        if (i % 100) == 0:
            print '  Importing #%d: %s...' % (i, fp)
        #total_seen = get_total_seen()
        db.cur.execute('''select * from (select id, seen,
        abs((select record_tls_version from fingerprints where id=%s) - record_tls_version) +
        abs((select ch_tls_version from fingerprints where id=%s) - ch_tls_version) +
        u16_lev((select cipher_suites from fingerprints where id=%s), cipher_suites) +
        u8_lev((select compression_methods from fingerprints where id=%s), compression_methods) +
        u16_lev((select extensions from fingerprints where id=%s), extensions) +
        u16_lev_skiphdr((select named_groups from fingerprints where id=%s), named_groups) +
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
                    [fp]*14)


        rows = db.cur.fetchall()
        related = []

        dists[fp] = {}
        for row in rows:
            c_id, c_seen, lev_dist = row
            if lev_dist < 0:
                print 'Error: lev_dist < 0:'
                print '  fp: %s' % (fp)
                print '  c_id: %s' % (c_id)
                print '  lev_dist: %d' % (lev_dist)
            if c_seen > 1000 and lev_dist < MAX_LEV_DIST and c_id != fp:
                if lev_dist not in dists[fp]:
                    dists[fp][lev_dist] = set()
                dists[fp][lev_dist].add(c_id)

    return dists


def load_fp_dists_from_file(fname='lev-dists.data'):
    import pickle
    dists = None
    with open(fname, 'r') as f:
        dists = pickle.load(f)
    return dists


def write_fp_dists_to_file(dists, fname='lev-dists.data'):
    print 'Writing to "%s"...' % (fname)
    with open(fname, 'w') as f:
        pickle.dump(dists, f, pickle.HIGHEST_PROTOCOL)
    print 'Done'



### Use the DB:
dists = load_fp_dists_from_db()
write_fp_dists_to_file(dists)

### Or use a local cached object:
#dists = load_fp_dists_from_file()

print 'Done importing %d fingerprints' % len(dists)

###############


LEV_DIST = 5
groups = []
any_group = set()   # if in this set, it's already in a cluster

def add_fp_neighbors(fp, lev_dist=1):
    cluster = set()
    cluster.add(fp)

    if fp in any_group or fp not in dists:
        return cluster

    any_group.add(fp)
    for d in xrange(lev_dist+1):
        if d not in dists[fp]:
            continue
        for peer_fp in dists[fp][d]:
            cluster = cluster.union(add_fp_neighbors(peer_fp, lev_dist))
    return cluster

# DFS dists matrix/thing
i = 0
for fp in dists.keys():
    i += 1
    if fp in any_group:
        continue
    groups.append(add_fp_neighbors(fp, LEV_DIST))

print '%d unique groups, containing %d fingerprints' % (len(groups), len(any_group))
sorted_groups = sorted(groups, key=lambda x: len(x), reverse=True)

print 'Largest group: %d fingerprints' % (len(sorted_groups[0]))


def insert_edges(sorted_groups, max_dist=LEV_DIST):
    cluster_rank = 1
    num_edges = 0
    edges_inserted = {}
    # Clear the table (don't worry, this starts a transaction...)
    db.cur.execute('TRUNCATE TABLE cluster_edges')
    for group in sorted_groups:
        for fp in group:
            for d in dists[fp].keys():
                if d > max_dist:
                    continue
                if d < 0:
                    print 'Hey fp %d has negative levs: %d' % (fp, d)
                    print dists[fp][d]
                    #print dists[fp]
                for peer_fp in dists[fp][d]:
                    if peer_fp not in group:
                        # I think we can skip this check...?
                        continue
                    #print 'Cluster #%d: %s -%d-> %s' % (cluster_rank, fp, d, peer_fp)
                    db.cur.execute('''INSERT INTO cluster_edges (source, dest, lev, cluster_rank)
                        VALUES (%s, %s, %s, %s)''',
                        (fp, peer_fp, d, cluster_rank))
                    edges_inserted[cluster_rank] = True
                    num_edges += 1

        cluster_rank += 1
    #print 'Inserted only %d unique cluster ranks' % len(edges_inserted)
    return (cluster_rank-1, num_edges)


# Clear current table
clusters, edges = insert_edges(sorted_groups)
print 'Inserted %d clusters with %d edges total' % (clusters, edges)
db.conn.commit()
