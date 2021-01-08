import socket

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
    else:
        return dns_dict[domain_list[-1]]


def update(dns_dict, domain_list, record):
    if domain_list[-1] not in dns_dict:
        return False
    elif len(domain_list) > 1:
        return update(dns_dict[domain_list.pop()], domain_list, record)
    else:
        dns_dict[domain_list[-1]] = record


def query(dns_dict, domain_name):
    record = socket.gethostbyname(domain_name)
    insert(dns_dict, domain_name.split('.'), record)
    return record
