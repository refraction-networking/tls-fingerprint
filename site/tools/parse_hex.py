#!/usr/bin/python

from parse_pcap import Fingerprint
import binascii
import argparse


def main():
	parser = argparse.ArgumentParser(description='Parses hex files.')
	parser.add_argument("input_file", help="Name of file to parse. It should start with \"160301\"", type=str)
	parser.add_argument('-s', '--sql-query-print', dest='PRINT_SQL', action='store_true',
						help="Print SQL query to add parsed fingerprints to databse")
	args = parser.parse_args()

	with open(args.input_file) as f:
		hex_str = f.read()
		bin_str = binascii.unhexlify(hex_str)
		fingerprint = Fingerprint.from_tls_data(bin_str)
		print '%s: %d' % (fingerprint.sni, fingerprint.id)
		if args.PRINT_SQL:
			fingerprint.print_sql()


if __name__ == "__main__":
	main()
