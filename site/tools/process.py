#!/usr/bin/python2.7
import argparse

VERBOSE = False

class FingerprintTracker:
	def __init__(self, input_filename):
		self.input_filename = input_filename
		fingerprints = dict()
		self.fingerprints_count = 0

		def add_fingerprint(line):
			split_line = line.split(' ', 3)
			if len(split_line) < 4:
				if VERBOSE:
					print line
			else:
				self.fingerprints_count += 1
				if split_line[2] in fingerprints:
					fingerprints[split_line[2]].count += 1
				else:
					fingerprints[split_line[2]] = Fingerprint(split_line[2], split_line[3])

		with open(input_filename, "r") as input:
			line = input.readline()
			if not line:
				raise AttributeError("Input file is empty.")
			add_fingerprint(line)
			while line:
				line = input.readline()
				add_fingerprint(line)

		self.fingerprints = sorted(fingerprints.values(), key=lambda f: f.count, reverse=True)
		print "Parsed " + str(self.fingerprints_count) + " fingerprints in " + self.input_filename +\
			  ": " + str(len(self.fingerprints)) + " of them are unique."

	def pprint(self):
		for v in self.fingerprints:
			print v

	def intersect(self, intersect_ft):
		for in_f in intersect_ft.fingerprints:
			print "\nSearching for " + str(in_f.hash) + " in " + self.input_filename
			in_f_hash = in_f.hash
			fingerprint_found = False
			for f in self.fingerprints:
				if in_f_hash == f.hash:
					print "Fingerprint " + in_f_hash + " was found " + str(f.count) + " times"
					print f
					fingerprint_found = True
					break
			if not fingerprint_found:
				print "Fingerprint " + in_f_hash + " was not found!"


class Fingerprint:
	def __init__(self, hash, str):
		self.hash = hash
		self.str = str
		self.count = 1

	def __str__(self):
		return str(self.count) + " [" + self.hash + "] " + self.str[:-1]

def main():
	parser = argparse.ArgumentParser(description='''Processes output of tls-fingerprint.
	If `--intersect intersect_file` is specified, shows if fingerprints from intersect_file are present in input_file.
	Otherwise, prints all fingerprints in input_file sorted by popularity''')
	parser.add_argument("input_file", help="Name of file to compile.", type=str)
	parser.add_argument('-v', '--verbose', dest='VERBOSE', action='store_true')
	parser.add_argument('-i', '--intersect', dest='intersect_file', type=str)
	args = parser.parse_args()

	ft = FingerprintTracker(args.input_file)
	if args.intersect_file:
		intersect_ft = FingerprintTracker(args.intersect_file)
		intersect_ft.pprint()
		ft.intersect(intersect_ft)
	else:
		ft.pprint()


if __name__ == "__main__":
	main()
