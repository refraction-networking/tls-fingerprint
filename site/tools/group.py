import pickle
import struct

import sys
sys.setrecursionlimit(10000)

dists = None

print 'Reading "lev-dists.data"...'
with open('lev-dists.data', 'r') as f:
    dists = pickle.load(f)
print 'Done. %d fingerprints loaded' % (len(dists))



LEV_DIST = 5

groups = []

any_group = set()  # if in this, it's already in a cluster


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


i = 0
for fp in dists.keys():
    i += 1
    if fp in any_group:
        continue

    #print 'Adding #%d: %s' % (i, fp)

    groups.append(add_fp_neighbors(fp, LEV_DIST))




print 'Done'
print '%d unique groups, contains %d fingerprints' % (len(groups), len(any_group))

confirm = set()

for g in groups:
    for fp in g:
        if fp in confirm:
            print 'Error: %s appears in more than one group' % fp
        confirm.add(fp)

#print 'Confirm: %d fingerprints' % (len(confirm))
if len(confirm) != len(any_group):
    print 'Error: mismatch between fingerprints. Is dataset symmetric?'

m = 0
biggest_group = None
fav_groups = []
for g in groups:
    if len(g) > m:
        m = len(g)
        biggest_group = g.copy()



fav_groups = sorted(groups, key=lambda x: len(x), reverse=True)[:4]


print 'Largest cluster: %d fingerprints' % (len(biggest_group))

def get_hid(nid):
    return struct.pack('!q', int(nid)).encode('hex')

def get_nid(hid):
    nid, = struct.unpack('!q', hid.decode('hex'))
    return nid



def get_edges(group, max_dist=LEV_DIST, group_id=1):
    edges = []
    ids = []
    for fp in group:
        hid = get_hid(fp)
        ids.append('    {"id": "%s", "group": %d}' % (hid, group_id))


        for d in dists[fp].keys():
            if d > max_dist:
                continue
            for peer_fp in dists[fp][d]:
                if peer_fp not in group:
                    # ??
                    continue
                phid = get_hid(peer_fp)
                edge = '    {"source": "%s", "target": "%s", "value": %d}' % (hid, phid, d)
                edges.append(edge)

    return ids, edges

def group_to_d3(ids, edges):
    s = ''
    s += '{\n'
    s += '  "nodes": [\n'
    s += ',\n'.join(ids)
    s += '  ],\n'
    s += '  "links": [\n'
    s += ',\n'.join(edges)
    s += '  ]\n'
    s += '}\n'
    return s

def get_d3_edges(group, max_dist=LEV_DIST):
    ids, edges = get_edges(group, max_dist)
    return group_to_d3(ids, edges)

i = 0
for g in groups:
    if len(g) > 10:
        i += 1
        with open('./groups/dist%d/group-%d.json' % (LEV_DIST, i), 'w') as f:
            ids, edges = get_edges(g, group_id=1)
            f.write(group_to_d3(ids, edges))

print 'Wrote %d groups to ./groups/' % (i)




with open('fav-group.json', 'w') as f:
    ids = []
    edges = []
    i = 0
    for g in fav_groups:
        i += 1
        cur_ids, cur_edges = get_edges(g, group_id=i)
        ids += cur_ids
        edges += cur_edges

    f.write(group_to_d3(ids, edges))

print 'Wrote %d groups to fav-group.json' % (len(fav_groups))


sizes = sorted([len(g) for g in groups], reverse=True)
total = sum(sizes)
cumulative = 0

with open('group-sizes.dat', 'w') as f:

    i = 0
    for s in sizes:
        i += 1
        cumulative += s
        f.write('%d %0.6f %d\n' % (i, float(cumulative)/total, s))





