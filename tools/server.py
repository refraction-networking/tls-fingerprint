import socket, ssl
import threading
import dpkt
import sys
import time
import json
import hashlib
import struct
from prod import db
from parsepcap import Fingerprint

HOST = ''
PORT = int(sys.argv[1])
CERT = '/etc/letsencrypt/live/client.tlsfingerprint.io-0001/fullchain-combined.pem'
IFACE = 'eth0'

from BaseHTTPServer import BaseHTTPRequestHandler
from StringIO import StringIO

chello_lock = threading.RLock()
chello_map = {}  #(addr,port) => (time, client_hello)

db = db.get_conn_cur()

class HTTPRequest(BaseHTTPRequestHandler):
    def __init__(self, request_text):
        self.rfile = StringIO(request_text)
        self.raw_requestline = self.rfile.readline()
        self.error_code = self.error_message = None
        self.parse_request()

    def send_error(self, code, message):
        self.error_code = code
        self.error_message = message



def cleanup_map():
    global chello_lock, chello_map
    with chello_lock:
        for client in chello_map.keys():
            if chello_map[client][0] < (time.time() - 30):
                print 'Removing %s' % str(client)
                del chello_map[client]

def parse_ip_pkt(ip):
    global chello_lock, chello_map
    if ip.p != dpkt.ip.IP_PROTO_TCP:
        return
    tcp = ip.data
    if tcp.dport != PORT:
        return

    # Look for client hello
    tls = tcp.data
    if len(tls) == 0:
        return

    if tls[0] != '\x16':
        # Not a handshake
        return

    # check that we haven't already gotten data for this client
    client = (ip.src, tcp.sport)
    with chello_lock:
        if client in chello_map:
            return
        print 'Adding %s' % str(client)
        chello_map[client] = (time.time(), tls)


def capture_pkts(iface="eth0"):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0x0300)
    s.bind((iface, 0))
    next_run = time.time() + 120
    while True:
        pkt = s.recv(0xffff)
        eth = dpkt.ethernet.Ethernet(pkt)
        if eth.type == dpkt.ethernet.ETH_TYPE_IP:
            parse_ip_pkt(eth.data)

        # Periodically cleanup
        if next_run < time.time():
            cleanup_map()
            next_run = time.time() + 120



def bytea(d):
    return buffer(''.join([chr(x) for x in d]))

# TODO: check normalized fp in db
# record normalized if not seen
def add_useragent(out):
    fid = out['nid']
    try:
        db.cur.execute("SELECT * FROM fingerprints WHERE id=%s", [fid])
        rows = db.cur.fetchall()
        # if len(rows) == 0:
        #     # Unique fingerprint, need to insert
        #     db.cur.execute('''INSERT INTO fingerprints (id, record_tls_version, ch_tls_version,
        #                     cipher_suites, compression_methods, extensions, named_groups,
        #                     ec_point_fmt, sig_algs, alpn, key_share, psk_key_exchange_modes,
        #                     supported_versions, cert_compression_algs, record_size_limit)
        #                 VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)''',
        #     (fid, out['tls_version'], out['ch_version'], bytea(out['cipher_suites']),
        #     bytea(out['compression_methods']), bytea(out['extensions']), bytea(out['curves']),
        #     bytea(out['pt_fmts']), bytea(out['sig_algs']), bytea(out['alpn']),\
        #     bytea(out['key_share']), bytea(out['psk_key_exchange_modes']), \
        #     bytea(out['supported_versions']), bytea(out['cert_compression_algs']),\
        #     bytea(out['record_size_limit'])))
        
        # Instead we insert to useragents only when the fingerprint is seen before to reduce overhead
        if len(rows) > 0:
            db.cur.execute("INSERT INTO useragents (unixtime, id, useragent) VALUES (%s, %s, %s)",
                (int(time.time()), fid, out['agent']))
        db.conn.commit()
    except Exception as e:
        print 'add_useragent(%s) for original fp: %s' % (out, e)
        db.conn.rollback()

    # No matter if the original fingerprint is seen before, we still try to insert the normalized one
    norm_fid = out['norm_nid']
    try:
         # And check if the normalized fingerprint is seen before
        # db.cur.execute("SELECT * FROM fingerprints_norm_ext WHERE id=%s", [norm_fid])
        # rows = db.cur.fetchall()
        # if len(rows) > 0:
        db.cur.execute("INSERT INTO useragents (unixtime, id, useragent) VALUES (%s, %s, %s)",
            (int(time.time()), norm_fid, out['agent']))
        db.conn.commit()
    except Exception as e:
        print 'add_useragent(%s) for normalized fp: %s' % (out, e)
        db.conn.rollback()


def handle(conn, db_lock):
    global chello_lock, chello_map
    buf = ''
    while True:
        req = conn.recv()
        if req == '':
            break
        buf += req
        if '\r\n\r\n' in buf:
            break


    ob = HTTPRequest(buf)
    user_agent = ''
    if 'user-agent' in ob.headers:
        user_agent = ob.headers['user-agent']

    addr, port = conn.getpeername()
    print 'Req (%s:%d): %s' % (addr, port, buf.encode('hex'))

    out = {}
    out['addr'] = addr
    out['port'] = port
    out['agent'] = user_agent
    #out['client_hello'] = ''

    resp = '{"status": "error"}\n'
    client_hello = None
    with chello_lock:
        k = (socket.inet_aton(addr), port)
        if k in chello_map:
            client_hello = chello_map[k][1]

    if client_hello is not None:
        out['client_hello'] = client_hello.encode('hex')
        # Parse it
        fp = Fingerprint.from_tls_data(client_hello)
        if fp is not None:
            #tls_version, chello_version, cipher_suites, comp_methods, exts, curves, pt_fmts, sig_algs, alpn, key_share, psk_key_exchange_modes, supported_versions, cert_comp_algs, record_size_limit, sni_host = res
            out['tls_version']          = fp.tls_version
            out['ch_version']           = fp.ch_version
            out['cipher_suites']        = fp.cipher_suites
            out['compression_methods']  = fp.comp_methods
            out['extensions']           = fp.extensions
            out['extensions_norm']      = fp.extensions_norm
            out['curves']               = fp.elliptic_curves
            out['pt_fmts']              = fp.ec_point_fmt
            out['sig_algs']             = fp.sig_algs
            out['alpn']                 = fp.alpn
            out['key_share']            = fp.key_share
            out['psk_key_exchange_modes'] = fp.psk_key_exchange_modes
            out['supported_versions']   = fp.supported_versions
            out['cert_compression_algs']= fp.cert_compression_algs
            out['record_size_limit']    = fp.record_size_limit
            out['sni']                  = fp.sni


            fpid = fp.get_fingerprint()
            out['nid'] = fpid
            hid = struct.pack('!q', fpid)
            out['id'] = hid.encode('hex')

            norm_fpid = fp.get_fingerprint_norm()
            out['norm_nid'] = norm_fpid
            norm_hid = struct.pack('!q', norm_fpid)
            out['norm_id'] = norm_hid.encode('hex')

            t = int(time.time()) - 2*3600
            seen = 0
            rank = -1
            frac_seen = 0.0

            # TODO: also return N-id for normalized fingerprint
            with db_lock:
                #db.cur.execute('''select id, sum, rank from
                #    (select id, sum(count), rank() over(order by sum(count) desc) from
                #    measurements where unixtime < %s group by id) as ranked where id=%s''', [int(t), int(fp)])

                # TODO: optimize speed
                db.cur.execute('''SELECT id, seen, rank, q.cluster_rank, fps, cluster_seen
                            FROM mv_ranked_fingerprints_norm_ext_week
                            LEFT JOIN cluster_edges ON mv_ranked_fingerprints_norm_ext_week.id=cluster_edges.source
                            LEFT JOIN (SELECT cluster_rank, count(*) as fps, sum(seen) as cluster_seen
                                       FROM (SELECT source, cluster_rank, min(seen) as seen
                                             FROM cluster_edges
                                             LEFT JOIN mv_ranked_fingerprints_norm_ext_week ON cluster_edges.source=mv_ranked_fingerprints_norm_ext_week.id
                                             GROUP BY cluster_rank, source) as a
                                        GROUP BY cluster_rank) as q ON cluster_edges.cluster_rank=q.cluster_rank
                            WHERE id=%s limit 1;''', [int(norm_fpid)])
                rows = db.cur.fetchall()
                cluster = 0
                cluster_fps = 0
                cluster_seen = 0
                if len(rows) > 0:
                    _, seen, rank, cluster, cluster_fps, cluster_seen = rows[0]

                db.cur.execute('''select sum(seen) from mv_ranked_fingerprints_norm_ext_week''')
                rows = db.cur.fetchall()
                total = 1.0
                if len(rows) > 0 and rows[0][0] is not None:
                    total = rows[0][0]
                    frac_seen = float(seen) / int(total)


            def intor0(i):
                if i is None:
                    return 0
                return int(i)
            out['frac_seen'] = frac_seen
            out['seen'] = int(seen)
            out['rank'] = int(rank)
            out['cluster'] = intor0(cluster)
            out['cluster_fps'] = intor0(cluster_fps)
            out['cluster_seen'] = intor0(cluster_seen)
            out['cluster_frac'] = float(intor0(cluster_seen)) / int(total)
            out['seen_total'] = int(total)
            # TODO: also include normalized fp info (except clusters)
            # OUT['normal_unique_cnt']

    resp = json.dumps(out)
    conn.write('HTTP/1.1 200 OK\r\nContent-type: application/json\r\nContent-Length: %d\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n%s' % (len(resp), resp))

    conn.close()
    with db_lock:
        add_useragent(out)

def handle_accept(ssock, addr, db_lock):
    conn = None
    try:
        #conn = ssl.wrap_socket(ssock, certfile=CERT, ssl_version=3, server_side=True)
        conn = ssl.wrap_socket(ssock, certfile=CERT, server_side=True)
        print 'Connection from %s:%s' % (addr[0], addr[1])
        handle(conn, db_lock)
    except ssl.SSLError as e:
        print(e)
    finally:
        if conn is not None:
            conn.close()

def main():
    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((HOST, PORT))
    sock.listen(5)
    iface = IFACE

    t = threading.Thread(target=capture_pkts, args=(iface,))
    t.setDaemon(True)
    t.start()

    #context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    #context.load_cert_chain(certfile=CERT)  # 1. key, 2. cert, 3. intermediates
    #context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1  # optional
    #context.set_ciphers('EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH')
    db_lock = threading.RLock()

    while True:
        conn = None
        ssock, addr = sock.accept()


        t = threading.Thread(target=handle_accept, args=(ssock,addr,db_lock))
        t.setDaemon(True)
        t.start()

if __name__ == '__main__':
    main()
