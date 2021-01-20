import json
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
        :param header: dnslib.dns.DNSHeader
        :param questions: list
        """
        super().__init__(header, questions, rr, q, a, auth, ar)
        self.domain_list, self.dns_type, self.dns_class = self.get_question()
        self.id = self.get_header()

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

    def set_answer(self, dns_dict):
        """
        Set answer section in DNS packet.
        add_answer(*RR.fromZone("abc.com A 1.2.3.4"))
        add_answer(RR("abc.com",QTYPE.CNAME,ttl=60,rdata=CNAME("ns.abc.com")))
        """
        answer = self.search(dns_dict, self.domain_list, self.dns_type)
        self.add_answer(RR('.'.join(self.domain_list), self.dns_type, ttl=60, answer))

    def search(self, dns_dict, domain_list, dns_type):
        """
        Search DNS record in local cache.
        :param domain_list: list of domain_name
        :param dns_type: str
        """
        d = dns_dict
        n = domain_list
        while n:
            if n[-1] not in d:
                return self.query(dns_dict, domain_list.join('.'), dns_type)
            else:
                d = d[n.pop()]
        if dns_type in d:
            return d[dns_type]
        for i in DNS_TYPES:
            if i in d:
                return d[i]
        return None

    def query(self, dns_dict, domain_name, dns_type):
        """
        Query Cloudflare DNS server and insert new record to cache.
        :param domain_name: str
        :param dns_type: str, e.g., 'A', 'NS'
        """
        base_url = 'https://cloudflare-dns.com/dns-query?'
        url = base_url + 'name=' + domain_name + '&type=' + dns_type
        r = requests.get(url, headers={'accept': 'application/dns-json'})
        try:
            answer = r.json()['Answer']
        except KeyError:
            return None
        else:
            record = []
            for item in answer:
                record.append(item['data'])
            self.insert(dns_dict, [dns_type] +
                        domain_name.split('.'), record)
            return record

    def insert(self, dns_dict, domain_list, record):
        """
        Insert and save DNS record in local cache.
        :param domain_list: list of [dns_type + domain_name]
        :param record: list of DNS record, e.g., ['1.1.1.1', '1.1.2.2']
        """
        if len(domain_list) > 1:
            if domain_list[-1] not in dns_dict:
                dns_dict[domain_list[-1]] = {}
            self.insert(dns_dict[domain_list.pop()], domain_list, record)
        else:
            dns_dict[domain_list[-1]] = record

    def update(self, dns_dict, domain_list, record):
        """Update DNS record in local cache."""
        if domain_list[-1] not in dns_dict:
            return False
        elif len(domain_list) > 1:
            return self.update(dns_dict[domain_list.pop()], domain_list, record)
        else:
            dns_dict[domain_list[-1]] = record
