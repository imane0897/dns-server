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
        q = DNSRecord.parse(data)
        q.set_answer()
        print(q)
        sock.sendto(str(q).encode('utf-8'), addr)


if __name__ == '__main__':
    main()
