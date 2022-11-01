#!/usr/bin/python

import argparse
import pcap
import dpkt
import binascii
import hashlib
import struct

PRINT_SQL = False


def ungrease_one(a):
	if (a & 0x0f0f) == 0x0a0a and (a & 0xf000) >> 8 == (a & 0x00f0):
		return 0x0a0a
	return a


def ungrease(x):
	return map(ungrease_one, x)


# Could use struct.parse, but meh. want arbitrary length arrays of base-256 data
def aint(arr):
	s = 0
	for a in arr:
		s *= 256
		s += ord(a)
	return s


fprints = {}


class Fingerprint:
	def __init__(self, tls_version, ch_version, cipher_suites, comp_methods, extensions,
				 elliptic_curves, ec_point_fmt, sig_algs, alpn, id, sni=""):
		self.tls_version = tls_version
		self.ch_version = ch_version
		self.cipher_suites = cipher_suites
		self.comp_methods = comp_methods
		self.extensions = extensions
		self.elliptic_curves = elliptic_curves
		self.ec_point_fmt = ec_point_fmt
		self.sig_algs = sig_algs
		self.alpn = alpn
		self.id = id
		self.sni = sni

	def print_sql(self):
		print "  INSERT INTO fingerprints (id, record_tls_version, ch_tls_version, cipher_suites, compression_methods, extensions, eliptic_curves, ec_point_fmt, sig_algs, alpn) VALUES (%d, %d, %d, '%s', '%s', '%s', '%s', '%s', '%s', '%s');" % \
			  (self.id, self.tls_version, self.ch_version, dbs(self.cipher_suites), dbs(self.comp_methods),
			   dbs(self.extensions),
			   dbs(self.elliptic_curves), dbs(self.ec_point_fmt), dbs(self.sig_algs), dbs(self.alpn))

	@staticmethod
	def from_tls_data(tls):
		if len(tls) == 0:
			return None
		if tls[0] != '\x16':
			# Not a handshake
			return None, ""
		tls_version = aint(tls[1:3])
		tls_len = aint(tls[3:5])
		hs_type = tls[5]
		if hs_type != '\x01':
			# not a client hello
			return None, ""

		if True:
			# Parse client hello
			chello_len = aint(tls[6:9])
			chello_version = aint(tls[9:11])
			rand = tls[11:11 + 32]
			off = 11 + 32

			# session ID
			sess_id_len = aint(tls[off])
			off += 1 + sess_id_len

			# print 'sess_id len %d (off %d)' % (sess_id_len, off)
			# print tls.encode('hex')

			# Cipher suites
			cs_len = aint(tls[off:off + 2])
			off += 2
			x = tls[off:off + cs_len]
			cipher_suites = list_u16_to_u8(ungrease([aint(x[2 * i:2 * i + 2]) for i in xrange(len(x) / 2)]))
			off += cs_len

			# Compression
			comp_len = aint(tls[off])
			off += 1
			comp_methods = [aint(x) for x in tls[off:off + comp_len]]
			off += comp_len

			# Extensions
			ext_len = aint(tls[off:off + 2])
			off += 2

			sni_host = ''
			curves = []
			pt_fmts = []
			sig_algs = []
			alpn = []
			exts = []
			end = off + ext_len
			while off < end:
				ext_type = aint(tls[off:off + 2])
				off += 2
				ext_len = aint(tls[off:off + 2])
				off += 2
				exts.append(ext_type)

				if ext_type == 0x0000:
					# SNI
					sni_len = aint(tls[off:off + 2])
					sni_type = aint(tls[off + 2])
					sni_len2 = aint(tls[off + 3:off + 5])
					sni_host = tls[off + 5:off + 5 + sni_len2]

				elif ext_type == 0x000a:
					# Elliptic curves
					# len...

					x = tls[off:off + ext_len]
					curves = list_u16_to_u8(ungrease([aint(x[2 * i:2 * i + 2]) for i in xrange(len(x) / 2)]))
				elif ext_type == 0x000b:
					# ec_point_fmt
					pt_fmt_len = aint(tls[off])
					pt_fmts = [aint(x) for x in tls[off:off + ext_len]]
				elif ext_type == 0x000d:
					# sig algs
					# Actually a length field, and actually these are 2-byte pairs but
					# this currently matches format...
					sig_algs = [aint(x) for x in tls[off:off + ext_len]]
				elif ext_type == 0x0010:
					# alpn
					# also has a length field...
					alpn = [aint(x) for x in tls[off:off + ext_len]]

				off += ext_len

			exts = list_u16_to_u8(ungrease(exts))
			id = Fingerprint.get_fingerprint(tls_version, chello_version, cipher_suites, comp_methods,
											 exts, curves, pt_fmts, sig_algs, alpn)
			return Fingerprint(tls_version, chello_version, cipher_suites, comp_methods,
							   exts, curves, pt_fmts, sig_algs, alpn, id, sni=sni_host)

	@staticmethod
	def get_fingerprint(tls_version, ch_version, cipher_suites, comp_methods, extensions,
						elliptic_curves, ec_point_fmt, sig_algs, alpn):

		def update_arr(h, arr):
			h.update(struct.pack('>L', len(arr)))
			h.update(''.join([chr(a) for a in arr]))

		h = hashlib.sha1()
		h.update(struct.pack('>HH', tls_version, ch_version))

		update_arr(h, cipher_suites)
		update_arr(h, comp_methods)
		update_arr(h, extensions)
		update_arr(h, elliptic_curves)
		update_arr(h, ec_point_fmt)
		update_arr(h, sig_algs)
		update_arr(h, alpn)

		out, = struct.unpack('>q', h.digest()[0:8])
		return out


def dbs(s):
	return '\\x' + ''.join(['%02x' % c for c in s])


def add_fingerprint(fingerprint):
	global fprints
	# r = re.compile('([a-z]+)([0-9]+)\_[0-9]+([a-z0-9]+)')  #fingerprints2
	# r = re.compile('([a-z]+)([0-9]+)\_([a-z0-9]+)')    # fingerprints5
	# matches = r.match(sni_host)
	# if matches is None:
	#    raise Exception('%s has no match' % sni_host)
	# browser = matches.group(1)
	# version = matches.group(2)
	# os = matches.group(3)

	# if os == 'windows7':
	#    os = 'win7'
	# elif os == 'osxsierra':
	#    os = 'osx'

	# f = '(%s, %s, %s, %s, %s, %s, %s, %s, %s)' % (tls_version, ch_version, cipher_suites, comp_methods, exts, curves, pt_fmts, sig_algs, alpn)
	if fingerprint.id not in fprints:
		fprints[fingerprint.id] = []
	# b = '%s_%s_%s' % (browser, version, os)
	print '%s: %s' % (fingerprint.sni_host, fingerprint.id)
	return

	b = sni_host.split('.')[0]
	if b not in fprints[f]:
		fprints[f].append(b)


# convert lists of u16 to list of u8s
def list_u16_to_u8(l):
	return [u8 for pair in [[u16 >> 8, u16 & 0xff] for u16 in l] for u8 in pair]


def parse_pcap(pcap_fname):
	global PRINT_SQL
	n = 0
	ret = []
	p = pcap.pcap(pcap_fname)
	for ts, pkt in p:
		try:
			n += 1
			try:
				eth = dpkt.ethernet.Ethernet(pkt)
				if eth.type != dpkt.ethernet.ETH_TYPE_IP:
					if eth.type == dpkt.ethernet.ETH_TYPE_PPPoE:
						if eth.data.data.p != 0x21:
							continue
						eth = eth.data.data
					else:
						continue
			except dpkt.dpkt.NeedData:
				eth = dpkt.sll.SLL(pkt)
				if eth.ethtype != dpkt.ethernet.ETH_TYPE_IP:
					continue

			ip = eth.data
			if ip.p != dpkt.ip.IP_PROTO_TCP:
				continue
			tcp = ip.data
			if tcp.dport != 443 and tcp.dport != 8443:
				continue

			fingerprint = Fingerprint.from_tls_data(tcp.data)
			if fingerprint is not None:
				ret.append((n, fingerprint.sni, fingerprint.id))
				if PRINT_SQL:
					fingerprint.print_sql()

		except Exception as e:
			print 'Error in pkt %d: %s' % (n, e)

	return ret


def parse_hex(hexfile_name):
	with open(hexfile_name) as f:
		hex_str = f.read()
		bin_str = binascii.unhexlify(hex_str)
		fingerprint = Fingerprint.from_tls_data(bin_str)
		print '%s: %d' % (fingerprint.sni, fingerprint.id)
		if PRINT_SQL:
			fingerprint.print_sql()


def main():
	parser = argparse.ArgumentParser(description='Parses pcap files')
	parser.add_argument("input_file", help="Name of file to parse.", type=str)
	parser.add_argument('-s', '--sql-query-print', dest='PRINT_SQL', action='store_true',
						help="Print SQL query to add parsed fingerprints to databse")
	args = parser.parse_args()

	global PRINT_SQL
	PRINT_SQL = args.PRINT_SQL

	fps = parse_pcap(args.input_file)
        uniq = {}
	for pkt_n, sni, fp in fps:
	    print '#%d %s: %d' % (pkt_n, sni, fp)
            if fp not in uniq:
                uniq[fp] = 0
            uniq[fp] += 1

        print '----'
        for fp, num in sorted(uniq.items(), key=lambda x: x[1], reverse=True):
            print '%d %s %d'  % (fp, struct.pack('!q', fp).encode('hex'), num)


if __name__ == "__main__":
	main()


# print 'fprints = {'
# for f in fprints.keys():
#    clients = fprints[f]
#    print "%s: %s," % (f, clients)
#    #print "'%s': %s," % (f, collapse(clients))
#    #print "'%s': %s => %s," % (f, clients, collapse(clients))
# print '}'

# print fprints
