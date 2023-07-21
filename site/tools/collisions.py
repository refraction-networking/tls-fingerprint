#!/usr/bin/python

from parsepcap import Fingerprint

from prod import db
import struct


def bytea_to_u16s(bya):
    return [ord(bya[2*a])*256 + ord(bya[2*a+1]) for a in xrange(len(bya)/2)]

def bytea_to_u8s(bya):
    return [ord(a) for a in bya]

def hid(nid):
    return struct.pack('!q', nid).encode('hex')

# Could use struct.parse, but meh. want arbitrary length arrays of base-256 data
def aint(arr):
    s = 0
    for a in arr:
        s *= 256
        s += ord(a)
    return s

old_to_new = {} # {old_id => [(new_id0, rank0, seen0, fp0), (newid1, rank1, seen1, fp1), ...]}


new_db = db.get_conn_cur()
old_db = db.get_old_cur()

db = new_db



old_db.cur.execute('select unixtime, id, useragent from useragents')
user_agents = {} # id => [(unixtime, useragent), ...]
user_agent_old_ids = set()  # set of old ids that we saw in the old db's useragent table
new_db_old_ids = set()  # set of old ids that we've seen in our new db
for row in old_db.cur.fetchall():
    unixtime, old_id, ua = row
    if old_id not in user_agents:
        user_agents[old_id] = []
    user_agents[old_id].append((unixtime, ua))

    user_agent_old_ids.add(old_id)

#print 'Read %d old useragents' % old_uas


db.cur.execute('select sum(seen) from mv_ranked_fingerprints')
rows = db.cur.fetchall()
total_seen = rows[0][0]

db.cur.execute('select * from fingerprints left join mv_ranked_fingerprints on fingerprints.id=mv_ranked_fingerprints.id order by rank')


for row in db.cur.fetchall():
    fpid, tls_version, ch_version, ciphers, comp_methods, exts, named_groups, ec_pt_fmt,\
        sig_algs, alpn, key_share, psk_key_ex_modes, supported_versions, cert_comp_algs,\
        record_size_limit, _, seen, rank = row


    fp = Fingerprint(tls_version, ch_version, bytea_to_u8s(ciphers), bytea_to_u8s(comp_methods),\
		bytea_to_u8s(exts), bytea_to_u8s(named_groups), bytea_to_u8s(ec_pt_fmt),\
 		bytea_to_u8s(sig_algs), bytea_to_u8s(alpn),\
                bytea_to_u8s(key_share), bytea_to_u8s(psk_key_ex_modes),\
		bytea_to_u8s(supported_versions), bytea_to_u8s(cert_comp_algs),\
                bytea_to_u8s(record_size_limit))

    new_id = fp.get_fingerprint()
    if new_id != fpid:
        print 'Error: fpid %s != %s?' % (fpid, new_id)

    old_id = fp.get_fingerprint_v1()
    new_db_old_ids.add(old_id)
    if old_id not in old_to_new:
        old_to_new[old_id] = []
    old_to_new[old_id].append((new_id, rank, seen, fp))


one_to_one = 0
print 'Sorting...'

sorted_old_to_new = sorted(old_to_new.items(), key=lambda row: min([x[1] if x[1] is not None else 999999999 for x in row[1]]))

diff_set = {} # {'key_share': 5, 'supported_versions': 10, ...}

i = 0
for old_id, news in sorted_old_to_new:
    if len(news) > 1:
        i += 1
        this_diff_set = set()
        #news = old_to_new[old_id]
        first_fp = news[0][3]
        min_rank = min([x[1] for x in news if x[1] is not None])
        max_seen = max([x[2] for x in news if x[2] is not None])
        #print news

        print '#%d Old ID %s: %s collisions, highest rank: %s (%0.2f%%)' % \
                (i, hid(old_id), len(news), min_rank, 100*float(max_seen)/float(total_seen))
        for new in news[1:]:
            other_fp = new[3]
            if first_fp.key_share != other_fp.key_share:
                this_diff_set.add('key_share')
            if first_fp.psk_key_exchange_modes != other_fp.psk_key_exchange_modes:
                this_diff_set.add('psk_key_ex')
            if first_fp.supported_versions != other_fp.supported_versions:
                this_diff_set.add('supported_versions')
            if first_fp.cert_compression_algs != other_fp.cert_compression_algs:
                this_diff_set.add('cert_comp_algs')
            if first_fp.record_size_limit != other_fp.record_size_limit:
                this_diff_set.add('record_size_limit')

        for new in news:
            if new[1] is not None:
                print '    %s %d (%0.3f%%)' % (hid(new[0]), new[1], 100*float(new[2])/float(total_seen))
            else:
                print '    %s N/A' % (hid(new[0]))
        print '    %s' % ', '.join(list(this_diff_set))

        for diff in this_diff_set:
            if diff not in diff_set:
                diff_set[diff] = 0
            diff_set[diff] += 1


        if old_id in user_agents:
            for unixtime, ua in user_agents[old_id]:
                print "-Wont add (%s, ?, %s)" % (unixtime, ua)

    else:
        one_to_one += 1
        # No collision, it's one-to-one, can add to clients...
        # This is ok because: the max unixtime from old db is 1544746106
        # and the min from new db is 1544749154, which is a few hours later
        new_id = news[0][0]
        if old_id in user_agents:
            for unixtime, ua in user_agents[old_id]:
                print '+Adding (%s, %s, %s)' % (unixtime, new_id, ua)
                #db.cur.execute('INSERT INTO useragents (unixtime, id, useragent) VALUES (%s, %s, %s)',
                #        (unixtime, new_id, ua))


#db.conn.commit()


print '----'
print '%d one-to-one out of %d' % (one_to_one, len(old_to_new))

for diff, num in diff_set.items():
    print '%s: %d' % (diff, num)


print '%d old IDs seen in useragents' % len(user_agent_old_ids)
print '%d old IDs seen in new DB' % len(new_db_old_ids)
print '%d old IDs seen in useragents NOT seen in new DB:' % len(user_agent_old_ids - new_db_old_ids)
for old_id in (user_agent_old_ids - new_db_old_ids):
    print '  %s:' % (hid(old_id))
    print '\n    '.join(list(set([x[1] for x in user_agents[old_id]])))

