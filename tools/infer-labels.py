#from tlsutil import *

import sys
sys.setrecursionlimit(10000)
import pickle
from prod import db
import random
import time
db = db.get_conn_cur('quic_fp')

sid_to_name = {}

db.cur.execute('TRUNCATE TABLE labels_inferred')
db.cur.execute('''select * from labels left join super_fingerprints on labels.id=super_fingerprints.id''')
rows = db.cur.fetchall()
for row in rows:
    sid, name, _, quic_fp, tls_fp, qtp_fp = row
    if tls_fp is None:
        print('Got null FP for %s (%s)' % (sid, name))
        continue

    # Observed
    if int(sid) in sid_to_name:
        if sid_to_name[int(sid)] != name:
            print('Error: %s already labeled %s, not %s' % (sid, sid_to_name[int(sid)], name))
            continue
        db.cur.execute('UPDATE labels_inferred SET observed=true where id=%s', [int(sid)])
    else:
        sid_to_name[int(sid)] = name
        db.cur.execute('INSERT INTO labels_inferred (id, name, observed) VALUES (%s, %s, true)', (sid, name))
    
    db.cur.execute('''select super_fingerprints.id, name from super_fingerprints left join labels on super_fingerprints.id=labels.id where tls_fp=%s''', [int(tls_fp)])
    # -7224755139223061243 | Edge 113       | -7224755139223061243 |  5290827952806019539 |  8114785661218601164 | -2839784197144064878
    for other_sid, other_name in db.cur.fetchall():
        if other_name is not None and other_name != name:
            print('Error: super_id %s and %s have different labels (%s, %s)' % (sid, other_sid, name, other_name))

        if int(other_sid) in sid_to_name:
            if name != sid_to_name[other_sid]:
                print('Error: conflicting name on %s: %s or %s?' % (other_sid, name, sid_to_name[int(other_sid)]))
                #sys.exit(1)
            print('Skipping %s: already assigned %s' % (other_sid, sid_to_name[int(other_sid)]))
            continue
        if int(other_sid) == int(sid):
            print('Weird, should not get here: %s' % sid)
            continue

        sid_to_name[other_sid] = name
        db.cur.execute('''INSERT INTO labels_inferred (id, name, observed) VALUES (%s, %s, false)''', (int(other_sid), name))
db.conn.commit()

#db.cur.execute('''INSERT INTO cluster_edges (source, dest, lev, cluster_rank)
#               VALUES (%s, %s, %s, %s)''',
#(fp, peer_fp, d, cluster_rank))
#db.conn.commit()
