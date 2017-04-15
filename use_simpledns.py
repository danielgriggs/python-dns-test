#!/usr/local/bin/python3

import simpledns
import pprint

pp = pprint.PrettyPrinter(indent=4)
sdns = simpledns.simpledns(debug=False)

results = dict()

domains = ['ninja.geek.nz.',
           'parasite.nt.nz.',
#           'google.com',
#           'facebook.com',
#           'arstechnica.com',
           'amazon.com.']

for domain in domains:
    results[domain] = sdns.direct_lookup(domain,'A')
    pp.pprint(results[domain])
