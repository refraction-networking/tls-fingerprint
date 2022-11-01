from prod import db
import csv
from collections import defaultdict
import pickle
import math

dbp = db.get_conn_cur("get_primed")
dbt = db.get_conn_cur()

rands = defaultdict(list)   # {client_random: [cid0, cid1, ...]}
cids = set()

MAX_LEV_DIST = 10
LEV_DIST = 5

def get_rands_from_db():
    with open('/home/ubuntu/crandom-dups.out', 'r') as f:
        for line in csv.reader(f):
            count, crandom = line
            if crandom == "\\x0000000000000000000000000000000000000000000000000000000000000000": continue
            print(crandom)
            dbp.cur.execute("SELECT cid FROM primers WHERE client_random=%s", [crandom])
            rows = dbp.cur.fetchall()
            for row in rows:
                print("  %s" % row[0])
                rands[crandom].append(row[0])
                cids.add(row[0])
    return rands



print('----')
def save_rands_to_file(rands, fname='/tmp/crandom-dups-cids.pickle'):
    with open(fname, 'w') as f:
        pickle.dump(rands, f, pickle.HIGHEST_PROTOCOL)

def load_rands_from_file(fname='/tmp/crandom-dups-cids.pickle'):
    with open(fname, 'r') as f:
        rands = pickle.load(f)
    return rands


#rands = get_rands_from_db()
#save_rands_to_file(rands)

rands = load_rands_from_file()

cids = set()
for cr, client_ids in rands.items():
    for cid in client_ids:
        cids.add(cid)
        if cid == -2284071891646513216:
            print('%s: %s' % (cr, client_ids))

print('Read %d fingerprints' % len(cids))



def get_dists_from_db():
    # Lev dists
    i = 0
    dists = {} # fp => { dist => set() of fingerprints $dist away
                # DFS to generate groups
    seen = {} # fp => number times seen
    for fp in cids:
        i += 1
        if (i % 100) == 0:
            print('  Importing #%d: %s...' % (i, fp))
    
        dbt.cur.execute('''select * from (select id, seen,
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
            as lev from (select fingerprints.*, seen from mv_ranked_fingerprints_week left join fingerprints on mv_ranked_fingerprints_week.id=fingerprints.id where seen > 1) as a order by lev) as q where lev < 10''', \
                        [fp]*14)
        rows = dbt.cur.fetchall()
        dists[fp] = defaultdict(set)
        for row in rows:
            c_id, c_seen, lev_dist = row
            if lev_dist < 0:
                print('Error: lev_dist < 0 for %s, %s (dist %d)' % (fp, c_id, lev_dist))
            if lev_dist < MAX_LEV_DIST and c_id != fp:
                dists[fp][lev_dist].add(c_id)
                seen[c_id] = c_seen

        if fp not in seen:
            dbt.cur.execute('''select seen from mv_ranked_fingerprints_week where id=%s''', [fp])
            rows = dbt.cur.fetchall()
            c_seen = 0
            if len(rows) != 0:
                c_seen = rows[0][0]
            seen[fp] = c_seen
    return dists, seen



def save_dists_to_file(dists, seen):
    with open('/tmp/crandom-dups-lev-dists.pickle', 'w') as f:
        pickle.dump((dists, seen), f, pickle.HIGHEST_PROTOCOL)

def load_dists_from_file():
    with open('/tmp/crandom-dups-lev-dists.pickle', 'r') as f:
        return pickle.load(f)


#dists, seen = get_dists_from_db()
#save_dists_to_file(dists, seen)
dists, seen = load_dists_from_file()
print('Got dists, %d seen len' % len(seen))

groups = []
any_group = set()

def add_fp_neighbors(fp, lev_dist=1):
    cluster = set()
    cluster.add(fp)
    if fp in any_group:
        return cluster
    if fp not in dists:
        #print('fp %d not in dists' % fp)
        return cluster

    any_group.add(fp)
    for d in xrange(lev_dist+1):
        if d not in dists[fp]:
            continue
        for peer_fp in dists[fp][d]:
            cluster = cluster.union(add_fp_neighbors(peer_fp, lev_dist))
    return cluster

for fp in dists.keys():
    if fp in any_group:
        continue
    groups.append(add_fp_neighbors(fp, LEV_DIST))

print('%d unique groups, containing %d fingerprints' % (len(groups), len(any_group)))
sorted_groups = sorted(groups, key=lambda x: len(x), reverse=True)
print('Largest group: %d fingerprints' % (len(sorted_groups[0])))
for i in xrange(10):
    print('Group %d: %d fingerprints' % (i, len(sorted_groups[i])))

cluster_rank = 1
edges = []  # List of edge tuples: (source_cid, dest_cid, lev_dist, cluster_rank)
for group in sorted_groups:
    added_edge = False
    for fp in group:
        if fp not in dists:
            #print('Warning: skipping %d, in cluster %d with %d others' % (fp, cluster_rank, len(group)))
            continue    # ??? This means a fp got in a group on its own?
        for d in dists[fp].keys():
            if d > LEV_DIST:
                continue
            if d < 0:
                print('Hey fp %d has negative levs: %d' % (fp, d))
                print(dists[fp][d])
            for peer_fp in dists[fp][d]:
                if peer_fp not in group:
                    continue
                # source: fp, dest: peer_fp, dist: d, cluster: cluster_rank
                added_edge = True
                edges.append((fp, peer_fp, d, cluster_rank))
    if not(added_edge):
        print('Skipped group %d entirely, size %d' % (cluster_rank, len(group)))
        for fp in group:
            print(fp)
    cluster_rank += 1
print('%d edges, %d clusters, %d groups' % (len(edges), cluster_rank-1, len(sorted_groups)))

#tot = sum(seen.values())
#for s in sorted(seen.values()):
#    if s == 0:
#        print(0)
#        continue
#    sz = int(4*math.log(float(s)))
#    cur = int(10000*float(s)/tot)
#    print(s,cur,sz)


with open('../data/crandom-dups-clusters.pickle', 'w') as f:
    pickle.dump((edges, seen, cids, rands), f, pickle.HIGHEST_PROTOCOL)

