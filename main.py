import socket
from dns_resolve import *

IP = '127.0.0.1'
PORT = 8123
# Trier tree structure
# :key  : domain name, DNS type
# :value: DNS records in dict
#       Answer={"name":"google.com","type":1,"TTL":161,"data":"172.217.11.78"}
#       Authority={"name":"com","type":6,"TTL":670,"data":"a.gtld-servers.net. nstld.verisign-grs.com. 1611319120 1800 900 604800 86400"}
DNS_CACHE = {}


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((IP, PORT))
    print('DNS is listening on {0}:{1} ...'.format(IP, PORT))

    while True:
        data, addr = sock.recvfrom(1024)
        q = DNSPacket.parse(data)
        a = q.reply()
        a.set_reply(DNS_CACHE)
        sock.sendto(a.pack(), addr)


if __name__ == '__main__':
    main()
