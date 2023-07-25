import psycopg
import psycopg2.extensions
import time
# Authors: Gaukas <Gaukas.Wang@colorado.edu>

# get_fp_stat: get the fingerprint stat of a fingerprint as a tuple. 
#
# return: (id, seen, rank, cluster_rank, cluster_fps, cluster_seen) or None if not found
#
# this function should be called with the db lock held if exists
def get_fp_stat(pgcursor: psycopg.Cursor|psycopg2.extensions.cursor, norm_fp_id: int):
    pgcursor.execute('''SELECT id, seen, rank, q.cluster_rank, fps, cluster_seen
                        FROM mv_ranked_fingerprints_norm_ext_week
                        LEFT JOIN cluster_edges ON mv_ranked_fingerprints_norm_ext_week.id=cluster_edges.source
                        LEFT JOIN (
                            SELECT cluster_rank, count(*) as fps, sum(seen) as cluster_seen
                            FROM (
                                SELECT source, cluster_rank, min(seen) as seen
                                FROM cluster_edges
                                LEFT JOIN mv_ranked_fingerprints_norm_ext_week ON cluster_edges.source=mv_ranked_fingerprints_norm_ext_week.id
                                GROUP BY cluster_rank, source
                            ) as a
                            GROUP BY cluster_rank
                        ) as q ON cluster_edges.cluster_rank=q.cluster_rank
                        WHERE id=%s limit 1;
                    ''', [norm_fp_id])
    return pgcursor.fetchone()

def record_useragent(pgconn: psycopg.Connection|psycopg2.extensions.connection, nid: int, normid: int, ua: str):
    with pgconn.cursor() as pgcursor:
        try:
            pgcursor.execute("SELECT * FROM fingerprints WHERE id=%s", [nid])
            rows = pgcursor.fetchall()
            
            # Insert to useragents only when the fingerprint is seen before to reduce WRITE overhead
            if len(rows) > 0:
                pgcursor.execute("INSERT INTO useragents (unixtime, id, useragent) VALUES (%s, %s, %s)",
                    (int(time.time()), nid, ua))
            pgconn.commit()
        except Exception as e:
            print('record_useragent(%d, %s) observed: %s' % (nid, ua, e))
            pgconn.rollback()

        # No matter if the original fingerprint is seen before, we still try to insert the normalized one
        try:
            # And check if the normalized fingerprint is seen before
            # db.cur.execute("SELECT * FROM fingerprints_norm_ext WHERE id=%s", [norm_fid])
            # rows = db.cur.fetchall()
            # if len(rows) > 0:
            pgcursor.execute("INSERT INTO useragents (unixtime, id, useragent) VALUES (%s, %s, %s)",
                (int(time.time()), normid, ua))
            pgconn.commit()
        except Exception as e:
            print('record_useragent(%d, %s) normalized: %s' % (normid, ua, e))
            pgconn.rollback()