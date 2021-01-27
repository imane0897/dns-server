import json
import time
import requests
from dnslib.dns import *

DNS_TYPES = ['A', 'NS', 'CNAME', 'SOA', 'NULL', 'PTR', 'HINFO', 'MX', 'TXT',
             'RP', 'AFSDB', 'SIG', 'KEY', 'AAAA', 'LOC', 'SRV', 'NAPTR', 'KX',
             'CERT', 'A6', 'DNAME', 'OPT', 'APL', 'DS', 'SSHFP',
             'IPSECKEY', 'RRSIG', 'NSEC', 'DNSKEY', 'DHCID', 'NSEC3',
             'NSEC3PARAM', 'TLSA', 'HIP', 'CDS', 'CDNSKEY', 'OPENPGPKEY',
             'SPF', 'TKEY', 'TSIG', 'IXFR', 'AXFR', 'ANY', 'URI', 'CAA', 'TA',
             'DLV']


class DNSPacket(DNSRecord):
    def __init__(self, header=None, questions=None, rr=None, q=None, a=None, auth=None, ar=None):
        """
        :param header   : dnslib.dns.DNSHeader
        :param questions: list
        dns_type: str, e.g., 'A', 'NS'
        """
        super().__init__(header, questions, rr, q, a, auth, ar)
        self.domain_list, self.dns_type, self.dns_class = self.get_question()
        self.id = self.get_header()

    def reply(self, ra=1, aa=1):
        super().reply(ra=1, aa=1)
        return DNSPacket(DNSHeader(id=self.header.id, bitmap=self.header.bitmap,
                                   qr=1, ra=ra, aa=aa), q=self.q)

    def get_header(self):
        """
        :returns: DNS packet ID
        """
        if self.header:
            return self.header.id
        return None

    def get_question(self):
        """
        :returns: tuple(list of domain name split by dot, dns type, dns class)
        """
        if self.questions:
            q = self.questions[0]
            return list(i.decode('utf-8') for i in q.qname.label), QTYPE.get(q.qtype), CLASS.get(q.qclass)
        else:
            return None, None, None

    def set_reply(self, dns_dict):
        """Set answer section in DNS packet."""
        self.set_answer(self.search(dns_dict))

    def set_answer(self, records):
        """
        Add answers:
            add_answer(*RR.fromZone("abc.com A 1.2.3.4"))
            add_answer(RR("abc.com",QTYPE.CNAME,ttl=60,rdata=CNAME("ns.abc.com")))
        """
        if isinstance(records, list):
            for i in records:
                self.add_answer(
                    *RR.fromZone(i['name'] + ' ' + QTYPE[i['type']] + ' ' + i['data'], ttl=i['TTL']))
        else:
            self.add_answer(
                *RR.fromZone(records['name'] + ' ' + QTYPE[records['type']] + ' ' + records['data'], ttl=records['TTL']))

    def search(self, dns_dict):
        """
        Search DNS record in local cache.
        :returns: list of DNS records, e.g., ['1.1.1.1', '1.1.2.2']
        """
        d = dns_dict
        n = self.domain_list.copy()
        while n:
            if n[-1] not in d:
                return self.query(dns_dict)
            else:
                d = d[n.pop()]
        if not n and 'name' in d and int(time.time()) - d['time'] < d['TTL']:
            return d
        return self.query(dns_dict)

    def query(self, dns_dict):
        """Query Cloudflare DNS server and insert new record to cache."""
        base_url = 'https://cloudflare-dns.com/dns-query?'
        domain_name = '.'.join(self.domain_list)
        url = base_url + 'name=' + domain_name + '&type=' + self.dns_type
        try:
            r = requests.get(
                url, headers={'accept': 'application/dns-json'}).json()
        except requests.exceptions.ProxyError:
            return []
        else:
            try:
                answer = r['Answer']
            except KeyError:
                try:
                    auth = r['Authority']
                except KeyError:
                    return []
                else:
                    for i in auth:
                        self.insert(dns_dict, self.domain_list, i)
                    return auth
            else:
                for i in answer:
                    self.insert(dns_dict, self.domain_list, i)
                return answer

    def insert(self, dns_dict, domain_list, record):
        """
        Insert and save DNS records in local cache.
        :param domain_list: list of domain_name split by dot
        :param record     : dict of DNS records, {"name":"google.com", "type":1,
                        "TTL":161,"data":"172.217.11.78", "time":_current_time}
        """
        if len(domain_list) > 1:
            if domain_list[-1] not in dns_dict:
                dns_dict[domain_list[-1]] = {}
            self.insert(dns_dict[domain_list.pop()], domain_list, record)
        else:
            record['time'] = int(time.time())
            dns_dict[domain_list[-1]] = record
