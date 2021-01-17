import socket
from dns_resolve import *

IP = '127.0.0.1'
PORT = 8123
DNS_CACHE = {}


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((IP, PORT))
    print('DNS is listening on {0}:{1} ...'.format(IP, PORT))

    while True:
        data, addr = sock.recvfrom(1024)
        
        result = response()
        # result = search(DNS_CACHE, domain_name.split('.'))
        # if not result:
            # result = query(DNS_CACHE, domain_name)
        # sock.sendto((' '.join(result or '') + '\n').encode(), addr)
        sock.sendto(str(result).encode(), addr)


if __name__ == '__main__':
    main()
