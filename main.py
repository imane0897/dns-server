import time
import socket
import threading
from dns_resolve import *

IP = '127.0.0.1'
PORT = 8123
"""
Trie tree structure
:key  : domain name, DNS type
:value: DNS records in dict
        "Answer":{"name":"google.com","type":1,"TTL":161,"data":"172.217.11.78"}
        "Authority":{"name":"com","type":6,"TTL":670,"data":"a.gtld-servers.net. nstld.verisign-grs.com. 1611319120 1800 900 604800 86400"}
"""
DNS_CACHE = {}


def clear_record(dns_dict, keys):
    """
    Remove records passed TTL by recursively visit the Trie DNS_CACHE
    :param dns_dict: current dict
    :param keys    : list of dns_dict's keys
    """
    for k in keys:
        if not isinstance(dns_dict[k], list):
            clear_record(dns_dict[k], list(dns_dict[k].keys()))
        else:
            r = dns_dict[k][0]
            if int(time.time()) - r['time'] >= r['TTL']:
                del dns_dict[k]


def clear():
    """Timed clear thread to remove out dated records"""
    while True:
        time.sleep(100)
        clear_record(DNS_CACHE, list(DNS_CACHE.keys()))
        print(DNS_CACHE)


def server(sock):
    while True:
        data, addr = sock.recvfrom(1024)
        q = DNSPacket.parse(data)
        a = q.reply()
        a.set_reply(DNS_CACHE)
        sock.sendto(a.pack(), addr)


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((IP, PORT))
    print('DNS is listening on {0}:{1} ...'.format(IP, PORT))

    t1 = threading.Thread(target=clear)
    t2 = threading.Thread(target=server, args=(sock,))
    t1.start()
    t2.start()
    t1.join()
    t2.join()


if __name__ == '__main__':
    main()
