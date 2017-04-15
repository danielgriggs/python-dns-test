#!/usr/bin/python3


import dns.resolver
import logging
import re
import sys

class simpledns(object):

    def __init__(self, mode='auto', debug=False):
        "Initalise a lookup object, automatic from resolvconf or manual"

        self.options = { 'edns': 0,
                         'payload': 2048 }
        self.options['options'] = [dns.edns.GenericOption(dns.edns.NSID, '')]

        if debug:
            logging.basicConfig(level=logging.DEBUG)
            logging.debug("Set debug logging")

        if mode is 'manual':
            self.auto = False
            logging.debug("Not autoconfiguring")
            # Don't set up a resolver.
        else:
            self.auto = True
            # Setup a resolver instance.
            # We'll assume they meant automatic.

        self.res = dns.resolver.Resolver(configure=self.auto)
        resolvers = ", ".join(self.res.nameservers)
        logging.debug("Using {} as default resolvers".format(resolvers))

        # Setup edns
        self.res.edns = self.options['edns']
        self.res.payload = self.options['payload']
        self.res.options = self.options['options']

    def lookup(self, qname, qtype='A', qclass='IN', TCP=False):
        "Lookup a record return just data."
        results = { 'packet': {} }
        try:
            logging.debug("Sending qname:{} qtype:{} qclass:{}"
            .format(qname,qtype,qclass))
            ans = self.res.query(qname, qtype, qclass, TCP)
        except dns.resolver.NoNameservers as error:
            results['packet']['error'] = True
            results['packet']['error_text'] = error.msg
        except dns.resolver.NXDOMAIN as error:
            results['packet']['error'] = True
            results['packet']['error_text'] = error.msg
        except dns.resolver.NoAnswer as error:
            results['packet']['error'] = True
            results['packet']['error_text'] = error.msg
        except:
            e = sys.exc_info()[0]
            results['packet']['error'] = True
            results['packet']['error_text'] = e
        else:
            results = _decode_answer(ans)

        return results

    def direct_lookup(self, qname, qtype='A', qclass='IN', TCP=False, where='8.8.8.8'):
        "Lookup a record return just data."
        results = { 'packet': {} }
        packet = dns.message.make_query(qname=qname,
                                        rdtype=qtype,
                                        rdclass=qclass,
                                        use_edns=self.options['edns'],
                                        payload=self.options['payload'])
        try:
            logging.debug("Sending qname:{} qtype:{} qclass:{}"
            .format(qname,qtype,qclass))
            if TCP:
                ans = dns.query.udp(packet,where)
            else:
                ans = dns.query.udp(packet,where)
        except dns.resolver.NoNameservers as error:
            results['packet']['error'] = True
            results['packet']['error_text'] = error.msg
        except dns.resolver.NXDOMAIN as error:
            results['packet']['error'] = True
            results['packet']['error_text'] = error.msg
        except dns.resolver.NoAnswer as error:
            results['packet']['error'] = True
            results['packet']['error_text'] = error.msg
        except:
            e = sys.exc_info()[0]
            results['packet']['error'] = True
            results['packet']['error_text'] = e
        else:
            results = _decode_response(ans)

        return results

    def set_search(self, list=None):
        "Change the resolver settings."
        if list == None:
            self.res.search = None
        else:
            names = []
            for name in list:
                names.append(dns.name.from_text(name,None))
            self.res.search = names

def _decode_answer(answer):
    "Decode the answer"
    _decode_response(answer.response)

def _decode_response(response):
    "Take a rrset and return contained data"
    results = { 'packet': {} }

#    logging.debug("Got answer for qclass:{} qtype:{} qname:{}"
#                format(answer.rdclass,answer.rdtype,answer.qname))

    results['packet']['id'] = response.id
    results['packet']['edns'] = _decode_edns(response)
    results['packet']['flags'] = _decode_flags(response.flags)
    results['packet']['rcode'] = _decode_rcode(response)
    results['packet']['opcode'] = _decode_opcode(response)
    results['authority'] = _decode_section(response.authority)
    results['answer'] = _decode_section(response.answer)
    results['additional'] = _decode_section(response.additional)
#    for rrset in answer.rrset:
#        print(dir(rrset))
#        print(rrset)
    return results

def _decode_section(section):
    "Decode the section if it exists"
    rrset = []
    if not section:
        return None

    for rr in section:
        aclass = _decode_rdclass(rr.rdclass)
        atype  = _decode_rdtype(rr.rdtype)
        logging.debug("Got RR {}:{}:{}".format(rr.name,rr.rdtype,rr.rdclass))
        for item in rr.items:
            logging.debug("Item: {}".format(item))
            rrset.append({ 'class': aclass,
                           'type': atype,
                           'ttl': rr.ttl,
                           'data': item.to_text()})

    return rrset

def _decode_data(item):
    "Decode known type of items for extra data."
    # Can't think what I need this for yet.
    # Other than MX and SOA records.
    pass

def _decode_rdtype(rdtype):
    "Takes a Response object and returns decoded TYPE"
    return dns.rdatatype.to_text(rdtype)

def _decode_rdclass(rdclass):
    "Takes a Response object and returns decoded CLASS"
    return dns.rdataclass.to_text(rdclass)

def _decode_opcode(response):
    "Takes a Response object and returns decoded OPCODE"
    return dns.opcode.to_text(response.opcode())

def _decode_rcode(response):
    "Takes a Response object and return decoded RCODE"
    rcode = dns.rcode.from_flags(response.flags,response.ednsflags)
    return dns.rcode.to_text(rcode)

def _decode_edns(response):
    "Takes a Response object and return all the edns data"
    edns = { 'enabled': False }

    if response.edns >= 0:
        edns['enabled'] = True
        edns['payload'] = response.payload
        edns['options'] = response.options

        for opt in response.options:
            if opt.otype == dns.edns.NSID:
                edns['nsid'] = opt.data

    return edns

def _decode_flags(flags):
    "Takes numeric flags and return as text list"
    if flags is 0:
        return []
    else:
        txt = dns.flags.to_text(flags)
        return re.split(' ',txt)

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
