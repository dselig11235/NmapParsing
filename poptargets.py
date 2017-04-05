#!/usr/bin/python

from nmaptools import NmapResults
from sys import argv
from nmaprules import classify
import csv

csv_filename = 'nmap.csv'
target_prefix = 'targets.'

results = NmapResults()
results.open(argv[1:])
classify(results.data)

types = set(type for rec in results.data for type in rec[4])
for t in types:
    targets = [rec[0] + ':' + rec[1] for rec in results.data if t in rec[4]]
    with open(target_prefix + t, 'w') as f:
        for tar in targets:
            f.write(tar + '\n')

data = [['IP Address', 'Port', 'Service', 'Version']]
data += results.data
with open(csv_filename, 'w') as f:
    csv.writer(f).writerows(data)
