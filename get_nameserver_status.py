#!/usr/bin/python3

import dns.resolver
import json
import pprint

pp = pprint.PrettyPrinter(indent=4)

results = dict()

domains = ['ninja.geek.nz',
           'parasite.net.nz',
           'google.com',
           'facebook.com',
           'arstechnica.com',
           'amazon.com']

def get_domain_nameserver_details(domain):
    results = {'ns': [], 'additional': {}}
    res = dns.resolver.Resolver(configure=True)
    try:
        ans = res.query(domain, 'NS')
    except:
        result['ns'] = None
    else:
        for rdata in ans:
            results['ns'].append(rdata.target.to_text())
        try:
            additional = ans.response.additional
        except:
            pass
        finally:
            results['additional'] = {}
            for rrset in additional:
                if rrset.name.to_text() not in results['additional']:
                    results['additional'][rrset.name.to_text()] = {}
                if rrset.rdtype not in results['additional'][rrset.name.to_text()]:
                    results['additional'][rrset.name.to_text()][str(rrset.rdtype)] = []
                for item in rrset.items:
                    results['additional'][rrset.name.to_text()][str(rrset.rdtype)].append(item.address)
                
    return results

for domain in domains:
    details = get_domain_nameserver_details(domain)
    pp.pprint( details )
