import json
import requests

def insert(dns_dict, domain_list, record):
    if len(domain_list) > 1:
        if domain_list[-1] not in dns_dict:
            dns_dict[domain_list[-1]] = {}
        insert(dns_dict[domain_list.pop()], domain_list, record)
    else:
        dns_dict[domain_list[-1]] = record


def search(dns_dict, domain_list):
    if domain_list[-1] not in dns_dict:
        return None
    elif len(domain_list) > 1:
        return search(dns_dict[domain_list.pop()], domain_list)
    elif not isinstance(dns_dict[domain_list[-1]], dict):
        return dns_dict[domain_list[-1]]
    else:
        return None


def update(dns_dict, domain_list, record):
    if domain_list[-1] not in dns_dict:
        return False
    elif len(domain_list) > 1:
        return update(dns_dict[domain_list.pop()], domain_list, record)
    else:
        dns_dict[domain_list[-1]] = record


def query(dns_dict, domain_name):
    base_url = 'https://cloudflare-dns.com/dns-query?'
    dns_type = 'A'
    url = base_url + 'name=' + domain_name + '&type=' + dns_type
    headers = {'accept': 'application/dns-json'}
    r = requests.get(url, headers=headers)
    try:
        answer = r.json()['Answer']
    except KeyError:
        return None
    # FIXME: other types of exceptions
    except:
        return None
    else:
        record = []
        for item in answer:
            record.append(item['data'])
        insert(dns_dict, domain_name.split('.'), record)
        return record
