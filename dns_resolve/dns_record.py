import json
import requests
from dnslib.dns import *


class DNSPacket(DNSRecord):
    def __init__(self, header=None, questions=None,
                 rr=None, q=None, a=None, auth=None, ar=None):
        super().__init__(header, questions,
                         rr, q, a, auth, ar)
        self.domain_name, self.dns_type, self.dns_class = self.get_question()
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

    def set_answer(self):
        """
        Set answer section in DNS packet.
        """
        pass

    def insert(dns_dict, domain_list, record):
        """
        Insert and save DNS record in local cache.
        """
        if len(domain_list) > 1:
            if domain_list[-1] not in dns_dict:
                dns_dict[domain_list[-1]] = {}
            insert(dns_dict[domain_list.pop()], domain_list, record)
        else:
            dns_dict[domain_list[-1]] = record

    def search(dns_dict, domain_list):
        """
        Search DNS record in local cache.
        """
        if domain_list[-1] not in dns_dict:
            return None
        elif len(domain_list) > 1:
            return search(dns_dict[domain_list.pop()], domain_list)
        elif not isinstance(dns_dict[domain_list[-1]], dict):
            return dns_dict[domain_list[-1]]
        else:
            return query(dns_dict, domain_list.join('.'))

    def update(dns_dict, domain_list, record):
        """
        Update DNS record in local cache.
        """
        if domain_list[-1] not in dns_dict:
            return False
        elif len(domain_list) > 1:
            return update(dns_dict[domain_list.pop()], domain_list, record)
        else:
            dns_dict[domain_list[-1]] = record

    def query(dns_dict, domain_name, dns_type):
        """
        Query Cloudflare DNS server.
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
            insert(dns_dict, domain_name.split('.'), record)
            return record
