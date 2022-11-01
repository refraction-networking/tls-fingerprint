#!/bin/bash


curl https://tlsfingerprint.io/data/generic/sniless-cdf > sniless-cdf
curl https://tlsfingerprint.io/data/generic/cdf-sfingerprints > cdf-sfingerprints
curl https://tlsfingerprint.io/data/generic/cdf-fingerprints > cdf-fingerprints



gnuplot cdf.gnuplot

curl https://tlsfingerprint.io/data/generic/total-measurements > total-measurements
./smooth.py total-measurements > total-smooth
gnuplot total.gnuplot


# reads cipher-order.out, made on rockymarmot with tools/cipher-order.py
gnuplot cipher-order.gnuplot



curl https://tlsfingerprint.io/data/generic/new-fingerprints > new-fingerprints
curl https://tlsfingerprint.io/data/generic/cumulative-unique > tot-uniq
curl https://tlsfingerprint.io/data/generic/cumulative-unique-1k > cumulative-unique-1k
curl https://tlsfingerprint.io/data/generic/cumulative-unique-10k > cumulative-unique-10k
gnuplot new-fingerprints.gnuplot
gnuplot tot-uniq.gnuplot
