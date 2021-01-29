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
        :param records: list of DNS answer
        """
        for i in records:
            self.add_answer(
                *RR.fromZone(i['name'] + ' ' + QTYPE[i['type']] + ' ' + i['data'], ttl=i['TTL']))

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
        if not n and isinstance(d, list):
            # now d is list (dict value), not dict
            for i in d:
                if int(time.time()) - i['time'] > i['TTL']:
                    return self.query(dns_dict)
        return d

    def query(self, dns_dict):
        """
        Query Cloudflare DNS server and insert new record to cache.
        :var r:
        {'Status': 0,
        'TC': False,
        'RD': True,
        'RA': True,
        'AD': False,
        'CD': False,
        'Question': [{'name': 'qq.com', 'type': 1}],
        'Answer': [{'name': 'qq.com', 'type': 1, 'TTL': 59, 'data': '125.39.52.26'},
        {'name': 'qq.com', 'type': 1, 'TTL': 59, 'data': '58.250.137.36'},
        {'name': 'qq.com', 'type': 1, 'TTL': 59, 'data': '58.247.214.47'}]}
        """
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
                    self.insert(dns_dict, self.domain_list, auth)
                    return auth
            else:
                self.insert(dns_dict, self.domain_list, answer)
                return answer

    def insert(self, dns_dict, domain_list, record):
        """
        Insert and save DNS records in local cache.
        :param domain_list: list of domain_name split by dot
        :param record     : list of DNS records, [{"name":"google.com", 
                            "type":1, "TTL":161,"data":"172.217.11.78", 
                            "time":_current_time}]
        """
        n = domain_list.copy()
        if len(n) > 1:
            if n[-1] not in dns_dict:
                dns_dict[n[-1]] = {}
            self.insert(dns_dict[n.pop()], n, record)
        else:
            t = int(time.time())
            for i in record:
                i['time'] = t
            dns_dict[n[-1]] = record
