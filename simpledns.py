#!/usr/bin/python3

import dns.resolver
import json
import pprint

class simpledns(object):

    def __init__(self, mode='auto'):
        "Initalise a lookup object, automatic from resolvconf or manual"
        self.mode = mode

        if mode is 'auto':
            pass
            # Setup a resolver instance.
        elif mode is manual:
            pass
            # Don't set up a resolver.
        else:
            # This is an error.
            pass

        
    def lookup(self, name, type='A', class='IN', TCP=False):
        "Lookup a record return just data."
        pass

    def set(self, key=None, value=None):
        "Change the resolver settings."
        pass


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
