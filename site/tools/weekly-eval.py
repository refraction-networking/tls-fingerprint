#!/usr/bin/python
from prod import db
import time
import datetime

# timestamps are mondays, UTC
ts_04_Dec_17 = 1512345600  # first week since last important change
ts_29_Jan_18 = 1517184000  # last week of desired chunk
ts_23_Apr_18 = 1524441600  # having data since Apr 19, Thu
day_in_seconds = 60 * 60 * 24


def fmt_ts(ts):
    return datetime.datetime.fromtimestamp(ts).strftime('%Y.%m.%d %H:%M')


def union(elem1, elem2):
    set1 = set(elem1)
    set2 = set(elem2)
    return set1.union(set2)


def intersection(elem1, elem2):
    set1 = set(elem1)
    set2 = set(elem2)
    return set1.intersection(set2)


def jaccard_index(elem1, elem2):
    intersection_len = len(intersection(elem1, elem2))
    union_len = (len(elem1) + len(elem2)) - intersection_len
    if union_len == 0:
        return 0
    return float(intersection_len) / union_len


db = db.get_conn_cur()

days = 7

thresholds_to_check = [10, 100, 1000, 10000, 100000]
fp_threshold_ids = dict()
prev_fp_threshold_ids = dict()
first_fp_threshold_ids = dict()

tops_to_check = [10, 100, 10000]
fp_top_ids = dict()  # idx is top number
prev_fp_top_ids = dict()  # idx is top number
first_fp_top_ids = dict()  # idx is top number

first_fp_id_conn = dict() # (id) -> conn
wlist_threshold_add = 10  # how many times seen on first week to get in whitelist
wlist_thresholds_block = [100, 1000, 10000]  # how many times seen to stay unblocked
whitelist_weekly_rates_fp = dict()
whitelist_weekly_rates_conn = dict()

for week_n in xrange(0, 30):
    start_ts = ts_04_Dec_17 + week_n * 7 * day_in_seconds
    end_ts = start_ts + day_in_seconds * days
    if start_ts > int(time.time()):
        break
    print "From {} ({}) to {} ({}):". \
        format(start_ts, fmt_ts(start_ts),
               end_ts, fmt_ts(end_ts))

    print "+-----------------+-------------+----------+----------------+----------------+"
    print "| Sample          | Size        | Test     | vs first week  | vs last week   |"
    print "+-----------------+-------------+----------+----------------+----------------+"

    # GET SIMILARITY OF ALL FPS THAT WERE SEEN > THRESHOLD TIMES
    for th in thresholds_to_check:
        query = "select count(*) from (select id, sum(count) as c from measurements where unixtime > {} and unixtime < {} group by id) as s where c > {};". \
            format(start_ts, end_ts, th)
        db.cur.execute(query)
        rows = db.cur.fetchall()

        count = rows[0][0]

        query = "select * from (select id, sum(count) as c from measurements where unixtime > {} and unixtime < {} group by id) as s where c > {};". \
            format(start_ts, end_ts, th)
        db.cur.execute(query)
        rows = db.cur.fetchall()
        fp_threshold_ids[th] = [row[0] for row in rows]

        if week_n == 0:
            first_fp_threshold_ids[th] = fp_threshold_ids[th]
            print "| seen > {:<8} | {:<11} | {:<8} | {:<14} | {:<14} |". \
                format(th, count, "-", "", "")
        else:
            print "| seen > {:<8} | {:<11} | {:<8} | {:<14} | {:<14} |". \
                format(th, count, "Jaccard",
                       jaccard_index(fp_threshold_ids[th], first_fp_threshold_ids[th]),
                       jaccard_index(fp_threshold_ids[th], prev_fp_threshold_ids[th]))
            print "|                 |             | {:<8} | {:<14} | {:<14} |". \
                format("Overlap",
                       len(intersection(fp_threshold_ids[th], first_fp_threshold_ids[th])),
                       len(intersection(fp_threshold_ids[th], prev_fp_threshold_ids[th])))
            print "|                 |             | {:<8} | {:<14} | {:<14} |". \
                format("Union",
                       len(union(fp_threshold_ids[th], first_fp_threshold_ids[th])),
                       len(union(fp_threshold_ids[th], prev_fp_threshold_ids[th])))

        # whitelist experiment
        if th in wlist_thresholds_block:
            whitelist = set(first_fp_threshold_ids[wlist_threshold_add])

            unblocked_ids = set(fp_threshold_ids[th]).intersection(whitelist)

            fp_conn = dict(zip(fp_threshold_ids[th], [row[1] for row in rows]))

            conns_total = sum([row[1] for row in rows])
            conns_unblocked = sum([fp_conn[id] for id in unblocked_ids])
            if len(fp_threshold_ids[th]) == 0:
                whitelist_weekly_rates_fp[start_ts] = 0
            else:
                whitelist_weekly_rates_fp[start_ts] = float(len(unblocked_ids)) \
                                                      / len(fp_threshold_ids[th])
            if conns_unblocked == 0:
                whitelist_weekly_rates_conn[start_ts] = 0
            else:
                whitelist_weekly_rates_conn[start_ts] = float(conns_unblocked) / conns_total
            print "|                 |             | {:<8} | {:<14} | {:<14} |". \
                format("wl fp", whitelist_weekly_rates_fp[start_ts], "-")
            print "|                 |             | {:<8} | {:<14} | {:<14} |". \
                format("wl conn", whitelist_weekly_rates_conn[start_ts], "-")

        print "+-----------------+-------------+----------+----------------+----------------+"


        prev_fp_threshold_ids[th] = fp_threshold_ids[th]

    # COMPARE TOP 10/100/etc against each other weekly
    for top in tops_to_check:
        query = "select * from (select id, sum(count) as c from measurements where unixtime > {} and unixtime < {} group by id) as s order by c desc limit {};". \
            format(start_ts, end_ts, top)
        db.cur.execute(query)
        rows = db.cur.fetchall()

        fp_top_ids[top] = [row[0] for row in rows]
        if week_n == 0:
            first_fp_top_ids[top] = fp_top_ids[top]
            print "| top {:<11} | {:<11} | {:<8} | {:<14} | {:<14} |". \
                format(top, len(rows), "-", "", "")
        else:
            print "| top {:<11} | {:<11} | {:<8} | {:<14} | {:<14} |". \
                format(top, len(rows), "Jaccard",
                       jaccard_index(fp_top_ids[top], first_fp_top_ids[top]),
                       jaccard_index(fp_top_ids[top], prev_fp_top_ids[top]))
            print "|                 |             | {:<8} | {:<14} | {:<14} |". \
                format("Overlap",
                       len(intersection(fp_top_ids[top], first_fp_top_ids[top])),
                       len(intersection(fp_top_ids[top], prev_fp_top_ids[top])))
            print "|                 |             | {:<8} | {:<14} | {:<14} |". \
                format("Union",
                       len(union(fp_top_ids[top], first_fp_top_ids[top])),
                       len(union(fp_top_ids[top], prev_fp_top_ids[top])))
        print "+-----------------+-------------+----------+----------------+----------------+"

        prev_fp_top_ids[top] = fp_top_ids[top]

    print ""


print "whitelist_weekly_rates_fp"
print whitelist_weekly_rates_fp
print "whitelist_weekly_rates_conn"
print whitelist_weekly_rates_conn